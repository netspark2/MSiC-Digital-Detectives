import random
import string

w = "digitaldetectives"

c = string.ascii_uppercase + string.ascii_lowercase + string.digits

def rand():
    global c
    r = ""
    for i in xrange(17):
        r += c[random.randint(0,len(c)-1)]
    return r

d = False
for i in xrange(250):
    with open("file%i.txt" % i, "w+") as f:
        if not d:
            if random.randint(1,150) == 1:
                d != d
                print i
                f.write(w)
                continue
        f.write(rand())
