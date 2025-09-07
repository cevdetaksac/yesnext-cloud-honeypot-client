import re
p='client.py'
with open(p,'r',encoding='utf-8') as f:
    data=f.read()
new = re.sub(r'(?m)^__version__.*$', '__version__ = "1.4.6"', data)
with open(p,'w',encoding='utf-8',newline='\r\n') as f:
    f.write(new)
print('done')