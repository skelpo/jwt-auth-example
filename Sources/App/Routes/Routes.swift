//  Created by Ralph Küpper on 12/07/17.
//  Copyright Skelpo Inc. 2017
//

import Vapor
import JWTProvider
import JWT

extension Droplet {
    func setupRoutes() throws {
        
        options("*") { request in
            return "options allowed"
        }
        
        let jwks:JSON = JSON(self.config["keys"]!.wrapped, self.config["keys"]!.context)
        let jwk:JSON = try jwks.get("keys")
        
        let signers = try SignerMap(jwks: jwks)
        
        let authController = AuthController(jwk: jwk[0]!, jwksUrl: jwksUrl, droplet: self)
        
        self.post("users/login", handler: authController.login)
        self.post("users/register", handler: authController.register)
        self.post("users/accessToken", handler: authController.accessToken)
        
        let tokenMiddleware = PayloadAuthenticationMiddleware<User>(signers, [ExpirationTimeClaim()], User.self)
        let errorMiddleware = ErrorMiddleware()
        
        self.grouped(errorMiddleware).group(tokenMiddleware) { authorized in
            authorized.get("users/status", handler: authController.status)
        }
    }
}
