import random
import string
def genRandomString(slen=10):
    return ''.join(random.sample(string.ascii_letters + string.digits,slen))

password = genRandomString()
print(password)