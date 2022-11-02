import os
import urllib.parse
import json

def get_file(my_dict):
    my_dict = urllib.parse.unquote(my_dict)
 
    my_dict = my_dict.replace("('", '*').replace("')", '**')
    my_dict = my_dict.replace("[", '***').replace("]", '****')
    my_dict = my_dict.replace("}'", '****').replace("'/", '*****').replace("'&", '******')
    my_dict = my_dict.replace("'", '"') \
        .replace('**',"')").replace('*',"('").replace('***',"[") \
        .replace('****',"]").replace('*****','}').replace('******',"'/") \
        .replace('*******',"'&").replace('"self"',"'self'").replace('"ambiente"',"'ambiente'") \
        .replace('"http://java.sun.com/jsp/jstl/functions"prefix="fn"',"'http://java.sun.com/jsp/jstl/functions'prefix='fn%'") \
        .replace(',"',",'").replace('"password"',"'password'").replace('?"', "?'").replace('"user"',"'user'") \
        .replace('"username"' ,"'username'").replace(' "X-Frame-Options", "DENY" ' ," 'X-Frame-Options', 'DENY' ") \
        .replace('" UPDATE products set price = price-1 where name = :1 "',"' UPDATE products set price = price-1 where name = :1' " ) \
        .replace('" <add name=‘Strict-Transport-Security’ value=‘max-age=31536000; includeSubDomains’/> "',"' <add name=‘Strict-Transport-Security’ value=‘max-age=31536000; includeSubDomains’/> " ) \
        .replace(' casewhenv_risk="RISK"then"Y"else"N" ' ," casewhenv_risk='RISK'then'Y'else'N' ")
    

    

    with open("data.json", "w") as text_file:
        text_file.write(my_dict)


    with open('data.json', encoding='utf-8') as f:
        csv_tmp = json.loads(f.read().encode('utf-8').decode())


    os.remove("data.json") 

    return csv_tmp