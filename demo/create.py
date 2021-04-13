from demo.utils import *
import json

if __name__ == "__main__":
    workspace_create = create_workspace(
        name="boltonshield",
        display_name="BoltonShield",
        admin_username="admin",
        admin_password='`g4rZNv)R=KhAx*Pk1(jhL11GAG_}&!~c9UDP|ei#9sF6yiAOT)v,&Wn?AdRAaD"',
    )

    token, user_sk = authenticate(
        workspace="boltonshield",
        username="admin",
        password='`g4rZNv)R=KhAx*Pk1(jhL11GAG_}&!~c9UDP|ei#9sF6yiAOT)v,&Wn?AdRAaD"',
    )

    workspace = get_workspace(token=token)
    print(json.dumps(workspace, indent=4))
