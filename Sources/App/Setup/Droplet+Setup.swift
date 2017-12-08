//  Created by Ralph Küpper on 12/07/17.
//  Copyright Skelpo Inc. 2017
//

@_exported import Vapor

extension Droplet {
    public func setup() throws {
        try setupRoutes()
        // Do any additional droplet setup
    }
}
