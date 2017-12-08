//
//  ErrorMiddleware.swift
//
//  Created by Ralph Küpper on 12/07/17.
//  Copyright Skelpo Inc. 2017
//

import Vapor
import JWTProvider
import Node
import JWT

final class ErrorMiddleware: Middleware {
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        do {
            return try next.respond(to: request)
            
        }
        catch let error as JWTError {
            throw Abort(
                .badRequest,
                reason: error.description
            )
        }
    }
}
