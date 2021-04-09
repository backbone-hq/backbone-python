from demo.utils import *
import json

if __name__ == "__main__":
    token, user_sk = authenticate(
        workspace="boltonshield",
        username="admin",
        password='`g4rZNv)R=KhAx*Pk1(jhL11GAG_}&!~c9UDP|ei#9sF6yiAOT)v,&Wn?AdRAaD"',
    )

    entry = create_entry(key="server_1234", value="my_secret_key", token=token)
    print(json.dumps(entry, indent=4))
