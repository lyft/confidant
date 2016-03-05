from flask.ext.script import Manager

import confidant.workarounds  # noqa
from confidant import app
from scripts.utils import ManageGrants
from scripts.utils import RevokeGrants

manager = Manager(app)

# Ensure KMS grants are setup for services
manager.add_command("manage_kms_auth_grants", ManageGrants)

# Revoke all KMS grants
manager.add_command("revoke_all_kms_auth_grants", RevokeGrants)

if __name__ == "__main__":
    manager.run()
