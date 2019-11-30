# python-fortnite

![python](https://img.shields.io/badge/python-3.X-blue.svg) ![Fortnite](https://img.shields.io/badge/Fortnite-v10.2.3-orange.svg)

A python lib to access the Fortnite API, supports 2FA and requires no reversing/SSL stripper.

# Requirements:

 * Linux *(due to the efficiency of [epoll](https://docs.python.org/3/library/select.html#select.epoll). Can change this if need arises)*
 * Python3+

No external libraries are used.

# Example:

> If you're using a new account, `EULA_ACCEPTED` needs to be `False` the first time you use the account.
> This in order for the client to *"accept"* the EULA which ultimately unlocks access to Fortnite API.
> Otherwise, the account will get rejected from quering the API *(most likely)*.

```python
from fortnite import *
client = Fortnite('henric@fnite.se', 'Password to account', EULA_ACCEPTED=True)

# YOUR OWN ID: client.logged_in_as

# Here's how to get other peoples information:
info = client.get_profile("0b0b6459d65f4665b16c9d9f520a5354")
print(info)
```

> The client automatically logs in, and gets ready to query for stats etc.
> `Fortnite()` caches the **2FA** verification during the scripts lifetime, but restarts require a new 2FA verification.

For a [asyncio](https://docs.python.org/3/library/asyncio.html) version that has more features, have a look at [fortnitepy](https://github.com/Terbau/fortnitepy)