//
//  User.swift
//
//  Created by Ralph Küpper on 12/07/17.
//  Copyright Skelpo Inc. 2017
//

import Vapor
import FluentProvider
import AuthProvider
import JWTProvider
import JWT

final class User: Model {
    let storage = Storage()
    
    var email: String
    var password: String
    
    typealias PayloadType = User
    
    static func authenticate(_ payload: PayloadType) throws -> User {
        return payload
    }
    
    init(_ email: String) throws {
        self.email = email
        self.password = ""
    }
    
    init(row: Row) throws {
        email = try row.get("email")
        password = try row.get("password")
    }
    
    // Serializes the Post to the database
    func makeRow() throws -> Row {
        var row = Row()
        try row.set("email", email)
        try row.set("password", password)
        return row
    }
    
}

extension User: JSONConvertible {
    convenience init(json: JSON) throws {
        try self.init(
            json.get("email")
        )
        self.id = try json.get("id")
    }
    
    func makeJSON() throws -> JSON {
        var json = JSON()
        try json.set("email", email)
        try json.set("id", id)
        return json
        
    }
    
    func makeProfileJSON() throws -> JSON {
        var json = JSON()
        try json.set("email", email)
        try json.set("id", id)
        return json
        
    }
}


extension User: Preparation {
    /// Prepares a table/collection in the database
    /// for storing Posts
    static func prepare(_ database: Database) throws {
        try database.create(self) { builder in
            builder.id()
            builder.string("email")
            builder.string("password")
        }
    }
    
    /// Undoes what was done in `prepare`
    static func revert(_ database: Database) throws {
        try database.delete(self)
    }
}

extension User: ResponseRepresentable { }

extension User: PayloadAuthenticatable { }

extension Request {
    func user() throws -> User {
        let user: User = try auth.assertAuthenticated()
        return user
    }
}



