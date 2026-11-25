//! Public group metadata shared by completions and offline help.

pub const CLIENT: &[&str] = &[
    "bootstrap",
    "completion",
    "configure",
    "connect",
    "credential",
    "help",
    "login",
    "logout",
    "start",
    "update",
    "version",
];
pub const LINUX: &[&str] = &[
    "config",
    "connector",
    "control",
    "controller",
    "exit",
    "id",
    "invite",
    "join",
    "node",
    "peers",
    "pki",
    "renew",
    "route",
    "routes",
    "status",
    "up",
];

pub type Commands = &'static [(&'static str, &'static str)];
pub const SHELLS: Commands = &[
    ("bash", "Generate Bash completion"),
    ("fish", "Generate Fish completion"),
    ("powershell", "Generate PowerShell completion"),
    ("zsh", "Generate Zsh completion"),
];

pub fn commands(path: &[&str]) -> Option<Commands> {
    match path {
        ["bootstrap"] => {
            return Some(&[
                ("download", "Download the verified platform package"),
                ("inspect", "Show advertised enrollment information"),
            ]);
        }
        ["completion"] => return Some(SHELLS),
        ["credential"] => {
            return Some(&[
                ("add", "Create a local proxy credential"),
                ("list", "List local proxy credentials"),
                ("remove", "Revoke a local proxy credential"),
            ]);
        }
        ["update"] => {
            return Some(if cfg!(target_os = "linux") {
                &[
                    ("client", "Update the local client"),
                    ("connector", "Update a managed Docker Connector"),
                    ("server", "Update the managed control plane"),
                ]
            } else {
                &[("client", "Update the local client")]
            });
        }
        _ if !cfg!(target_os = "linux") => return None,
        _ => {}
    }
    Some(match path {
        ["config"] => &[
            (
                "inspect-controller-initial-network",
                "Inspect immutable controller network configuration",
            ),
            ("validate", "Validate a Laneway configuration file"),
        ],
        ["connector"] => &[
            ("activate", "Enroll using a single-use Connector token"),
            (
                "bootstrap-activate",
                "Activate an encrypted bootstrap payload",
            ),
            ("bootstrap-seal", "Seal a short-lived bootstrap payload"),
            (
                "configure",
                "Validate or migrate persistent Connector configuration",
            ),
            ("run", "Start the Connector and activate if needed"),
            ("validate", "Validate persistent Connector identity"),
        ],
        ["control"] => &[
            ("init", "Initialize or validate the control plane"),
            ("user-token", "Issue a one-time local user token"),
            ("invite", "Issue a single-use enrollment command"),
            ("route", "Assign an approved Connector destination"),
            ("status", "Show deployed services and forwarding"),
            ("administrator", "Manage administrator access"),
            ("update", "Update to the latest stable release"),
            ("production-check", "Run production readiness checks"),
            ("backup", "Create an encrypted recovery bundle"),
            ("restore", "Restore an encrypted recovery bundle"),
            ("upgrade", "Upgrade with a prepared release environment"),
            ("rollback", "Roll back to the previous release selection"),
        ],
        ["control", "route"] => &[("add", "Assign a destination to a Connector")],
        ["control", "administrator"] => &[
            ("bootstrap", "Create administrator access"),
            ("recover", "Recover administrator access"),
            ("root-token", "Manage the root automation token"),
        ],
        ["control", "administrator", "root-token"] => {
            &[("rotate", "Rotate the root automation token")]
        }
        ["controller"] => &[
            ("overview", "Show a controller overview"),
            ("administrator", "Manage administrator access"),
            ("network", "Manage controller networks"),
            ("enrollment-token", "Issue enrollment tokens"),
            ("bootstrap-bundle", "Create a bootstrap bundle"),
            ("route", "Advertise and manage routes"),
            ("acl", "Manage access rules"),
            ("node", "Manage enrolled nodes"),
            ("certificate", "List or revoke certificates"),
            ("relay", "Manage relay registrations"),
            ("audit", "List controller audit events"),
        ],
        ["controller", "administrator"] => &[
            ("bootstrap", "Create administrator access"),
            ("recover", "Recover administrator access"),
            ("root-token", "Manage root automation tokens"),
        ],
        ["controller", "administrator", "root-token"] => &[
            ("generate", "Generate a root automation token"),
            ("authentication-check", "Verify token authentication"),
            ("rotation-begin", "Begin root-token rotation"),
            ("rotation-complete", "Complete root-token rotation"),
        ],
        ["controller", "network"] => &[
            ("create", "Create a network"),
            ("get", "Show a network"),
            ("list", "List networks"),
        ],
        ["controller", "relay"] => &[
            ("register", "Register a relay"),
            ("update", "Update a relay registration"),
            ("disable", "Disable a relay registration"),
            ("list", "List relays"),
        ],
        ["controller", "acl"] => &[
            ("add", "Add an access rule"),
            ("delete", "Delete an access rule"),
            ("list", "List access rules"),
        ],
        ["controller", "node"] => &[
            ("revoke", "Revoke an enrolled node"),
            ("capabilities", "Set node forwarding capabilities"),
            ("list", "List enrolled nodes"),
        ],
        ["controller", "certificate"] => &[
            ("revoke", "Revoke a certificate"),
            ("list", "List certificates"),
        ],
        ["controller", "enrollment-token"] => &[("issue", "Issue an enrollment token")],
        ["controller", "bootstrap-bundle"] => &[("create", "Create a bootstrap bundle")],
        ["route"] | ["node", "route"] | ["controller", "route"] => &[
            ("assign", "Assign an approved Connector destination"),
            ("advertise", "Advertise a route"),
            ("approve", "Approve a route"),
            ("withdraw", "Withdraw a route"),
            ("list", "List routes"),
        ],
        ["exit"] | ["node", "exit"] => &[
            ("enable", "Advertise this gateway as an exit node"),
            ("use", "Select an authorized exit node"),
            ("disable", "Return to split-tunnel routing"),
        ],
        ["node"] => &[
            ("install", "Enroll and install a managed node"),
            ("renew", "Rotate a managed node credential"),
            ("run", "Run the persistent node service"),
            ("uninstall", "Remove managed node state"),
            ("up", "Show whether the node is up"),
            ("status", "Show node status"),
            ("peers", "List peers"),
            ("routes", "List effective routes"),
            ("exit", "Configure exit-node routing"),
            ("route", "Advertise and manage routes"),
        ],
        ["pki"] => &[
            ("init", "Create a certificate authority"),
            ("intermediate", "Issue an intermediate authority"),
            ("verify-authority", "Verify an authority credential"),
            ("node", "Issue a node certificate"),
            ("relay", "Issue a relay certificate"),
            ("controller", "Issue a controller certificate"),
        ],
        _ => return None,
    })
}
