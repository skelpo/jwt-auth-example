//  Created by Ralph Küpper on 12/07/17.
//  Copyright Skelpo Inc. 2017
//

import App

let config = try Config()
try config.setup()

let drop = try Droplet(config)
try drop.setup()

try drop.run()
