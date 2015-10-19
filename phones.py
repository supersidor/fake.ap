import sqlite3
import re

a1 = re.compile('android\s+(\d.\d(?:.\d)?);\s+(?:\w{2}[_-]\w{2};)?\s*(.*)\sbuild',re.IGNORECASE);
vk = re.compile('^VKAndroidApp.*android\s+(\d.\d(?:.\d)?);\s.*?;\s.*?;\s(.*?);',re.IGNORECASE);

def update(cursor,mac,os,model):
    cursor.execute("UPDATE clients SET os=?,model=? WHERE mac=?",(os,model,mac))

def parse_agent(agent):
    m = a1.search(agent)
    if m:
        return ("Android "+m.group(1),m.group(2))
    m = vk.search(agent)
    if m:
        return ("Android "+m.group(1),m.group(2))
    return None

if __name__ == "__main__":
    con = sqlite3.connect('clients.db',detect_types=sqlite3.PARSE_DECLTYPES)
    c = con.cursor()
    c.execute("SELECT * FROM agents")
    nf = set()
    for a in c.fetchall():
        agent = a[1]
        info = parse_agent(agent)
        if info:
            model = info[1]
            model_lower = model.lower()
            if model_lower.find("samsung")==0:
                model = model[len("samsung")+1:]

            update(c,a[0],info[0],model)
            #print info[0],"\t",info[1]
        elif agent not in nf:
            nf = nf | {agent}
    con.commit()
    con.close()
    #for a in nf:
    #    print a
