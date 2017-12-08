//
//  UserController.swift
//
//  Created by Ralph Küpper on 12/07/17.
//  Copyright Skelpo Inc. 2017
//

import Foundation
import Vapor
import HTTP
import JWT
import Fluent
import CryptoSwift
import JWTProvider

final class AuthController {
    
    var jwk: JSON
    let clientFactory: ClientFactoryProtocol?
    let droplet: Droplet?
    
    init(jwk: JSON, droplet: Droplet) {
        self.clientFactory = EngineClientFactory()
        self.jwk = jwk
        self.droplet = droplet
    }
    
    func register(_ req: Request) throws -> ResponseRepresentable {
        guard let email: String = req.data["email"]?.string else {
            throw Abort(.badRequest, reason: "No email given.")
        }
        guard let password: String = req.data["password"]?.string else {
            throw Abort(.badRequest, reason: "No password given.")
        }
        
        let user = try User(email)
        user.password = password.md5() // just for demonstration purposes, in a real production environment always use safer ways to store passwords!
        try user.save()
        
        var json = JSON()
        try json.set("status", "success")
        return json
    }
    
    func status(_ req: Request) throws -> ResponseRepresentable {
        
        try req.user()
        
        var json = JSON()
        try json.set("status", "success")
        return json
    }
    
    func accessToken(_ req: Request) throws -> ResponseRepresentable {
        guard let refreshToken: String = req.data["refreshToken"]?.string else {
            throw Abort(.badRequest, reason: "No refresh token given.")
        }
        let jwt = try JWT(token: refreshToken)
        
        guard let kid = jwt.keyIdentifier else {
            // The token doesn't include a kid
            throw JWTProviderError.noVerifiedJWT
        }
        
        let jwks:JSON = JSON(droplet!.config["keys"]!.wrapped, droplet!.config["keys"]!.context)
        
        let signers = try SignerMap(jwks: jwks)
        
        guard let signer = signers[kid] else {
            throw JWTProviderError.noJWTSigner
        }
        
        // verify the signature
        try jwt.verifySignature(using: signer)
        
        // verify the claims
        try jwt.verifyClaims([ExpirationTimeClaim()])
        
        let userId: Int = try jwt.payload.get("id")
        
        guard let user = try User.makeQuery().find(userId) else {
            throw Abort(.badRequest, reason: "No user found.")
        }
        let headers = try getHeaders()
        
        let accessTokenData = try getAccessTokenData(user: user, exp: 3600)
        
        let accessJwt = try generateJWT(headers, accessTokenData)
        
        var json = JSON()
        try json.set("status", "success")
        try json.set("accessToken", accessJwt.createToken())
        return json
    }
    
    func login(_ req: Request) throws -> ResponseRepresentable {
        guard let email: String = req.data["email"]?.string else {
            throw Abort(.badRequest, reason: "No email given.")
        }
        guard let password: String = req.data["password"]?.string else {
            throw Abort(.badRequest, reason: "No password given.")
        }
        let users = try User.makeQuery().filter("email", .equals, email).limit(1, offset:0).all()
        if (users.count == 0) {
            throw Abort(.badRequest, reason: "No user found.")
        }
        if (users[0].password != password.md5()) {
            throw Abort(.badRequest, reason: "Wrong password.")
        }
        
        let headers = try getHeaders()
        
        let accessTokenData = try getAccessTokenData(user: users[0], exp: 3600)
        
        let jwt = try generateJWT(headers, accessTokenData)
        
        let refreshTokenData = try getRefreshTokenData(user: users[0], exp: 24*60*60*30)
        
        let refreshJwt = try generateJWT(headers, refreshTokenData)
        
        var json = JSON()
        try json.set("status", "success")
        try json.set("accessToken", jwt.createToken())
        try json.set("refreshToken", refreshJwt.createToken())
        return json
    }
    
    private func generateJWT(_ headers: JSON, _ data: JSON) throws -> JWT {
        let signer = try JWKSignerFactory(jwk: self.jwk).makeSigner()
        let jwt = try JWT(headers: headers, payload: data, signer: signer)
        return jwt
    }
    
    private func getHeaders() throws -> JSON {
        let kid: String = try self.jwk.get("kid")
        let alg: String = try self.jwk.get("alg")
        
        var headers = JSON()
        try headers.set("crit", [
            "exp",
            "aud"
            ])
        try headers.set("kid", kid)
        try headers.set("alg", alg)
        return headers
    }
    
    private func getRefreshTokenData(user: User, exp: Int) throws -> JSON {
        var refreshTokenData = JSON()
        try refreshTokenData.set("id", user.id)
        
        let sticks = Seconds(Date().timeIntervalSince1970)
        try refreshTokenData.set("iat", String(sticks))
        try refreshTokenData.set("exp", String(sticks+exp))
        return refreshTokenData
    }
    
    private func getAccessTokenData(user: User, exp: Int) throws -> JSON {
        var accessTokenData = JSON()
        try accessTokenData.set("email", user.email)
        try accessTokenData.set("id", user.id)
        let sticks = Seconds(Date().timeIntervalSince1970)
        try accessTokenData.set("iat", String(sticks))
        try accessTokenData.set("exp", String(sticks+exp))
        return accessTokenData
    }
}

