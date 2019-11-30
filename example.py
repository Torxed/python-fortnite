from fortnite import *

# If you're using a new account, EULA_ACCEPTED needs to be False the first time you use it.
# This in order for the client to "accept" the EULA which ultimately unlocks access to Fortnite API.
# Otherwise, the account will get rejected from quering the API.
client = Fortnite('henric@fnite.se', 'Q04nWZ4QyC', EULA_ACCEPTED=True)

# The client automatically logs in, and gets ready to query for stats etc.
# YOUR OWN ID: client.logged_in_as

# Here's how to get other peoples information:
info = client.get_profile("0b0b6459d65f4665b16c9d9f520a5354")
print(info)