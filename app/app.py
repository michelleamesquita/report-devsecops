
from crypt import methods
import re
from flask import Flask, request, redirect, url_for,render_template,jsonify,abort,send_from_directory,Response,send_file,escape
import json
from flask_mysqldb import MySQL
from flask_bootstrap import Bootstrap
import mysql.connector
import os
import pandas as pd
from werkzeug.utils import secure_filename
import csv
import numpy as np
import urllib.parse
from unicodedata import normalize
import os
from io import BytesIO
import xlsxwriter
import glob


app = Flask(__name__)
bootstrap = Bootstrap(app)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'key'
app.config['UPLOAD_PATH']= 'src'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.csv', '.png']



config = {
        'user': 'root',
        'password': 'root',
        'host': 'db',
        'port': '3306',
        'database': 'sec'
        }




@app.route("/get_csv/<my_dict>",methods=['GET'])
def get_csv(my_dict):

    my_dict = urllib.parse.unquote(my_dict)
    # my_dict = normalize('NFKD', my_dict).encode('ASCII','ignore').decode('ASCII')

    # my_dict = my_dict.replace("\'", "\"")
    
    # return my_dict

    # csv_tmp=json.loads(my_dict.replace("\'", "\""))  

    # replace text 
    my_dict = my_dict.replace('document.cookie = "ActionID=" + actionsArray[value] + "; expires=" + date.toUTCString() + "; path=/myApp/" + "; secure;" ' ,"document.cookie = 'ActionID=' + actionsArray[value] + '; expires=' + date.toUTCString() + '; path=/myApp/' + '; secure;' ")
    my_dict = my_dict.replace("Request['value']","Request['value']")
    my_dict = my_dict.replace('referer = Request.UrlReferrer != null ? Request.UrlReferrer.ToString() : "None"' ,"referer = Request.UrlReferrer != null ? Request.UrlReferrer.ToString() : 'None'")
    my_dict = my_dict.replace('builder["Persist Security Info"] = "False"' ,"builder['Persist Security Info'] = 'False'")
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
        .replace(' casewhenv_risk="RISK"then"Y"else"N" ' ," casewhenv_risk='RISK'then'Y'else'N' ") \
        .replace('"Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled"' ,"'Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled'") \
        .replace('builder["Persist Security Info"] = "False"' ,"builder['Persist Security Info'] = 'False'") \
        .replace('"Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled; Encrypt=true; TrustServerCertificate=true"' ,"'Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled; Encrypt=true; TrustServerCertificate=true'") \
        .replace('''Request')('"value"')')''' ,"(Request[param])") \
        .replace('''"None"''' ,"'None'") \
        .replace('''"param"''' ,"'param'") \
        .replace('''"true"''' ,"'true'") \
        .replace('''app.config')('"SESSION_COOKIE_SECURE "')') = True''' ,"app.config['SESSION_COOKIE_SECURE '] = True") \
        .replace('''// Data is stored in DOM, but not persistently ')')''' ,"// Data is stored in DOM, but not persistently }") \
        .replace('''document.cookie = "ActionID=" + actionsArray')('value')') + "; expires=" + date.toUTCString() + "; path=/myApp/" + "; secure;"''' , "document.cookie = 'ActionID=' + actionsArray')('value')') + '; expires=' + date.toUTCString() + '; path=/myApp/' + '; secure;'")
    

    

    with open("data.json", "w") as text_file:
        text_file.write(my_dict)


    with open('data.json', encoding='utf-8') as f:
        csv_tmp = json.loads(f.read().encode('utf-8').decode())


    #os.remove("data.json") 
   
    

    comp=[]
    name=[]
    date=[]
    vuln=[]
    detail=[]
    remediation=[]

    for key in csv_tmp.keys():
        if key.startswith('name'):
            name.append(csv_tmp[key])
        if key.startswith('comp'):
            comp.append(csv_tmp[key])
        if key.startswith('date'):
            date.append(csv_tmp[key])
        if ('vuln') in key:
            vuln.append(csv_tmp[key])
        if ('detail') in key:
            detail.append(csv_tmp[key])
        if ('remediation') in key:
            remediation.append(csv_tmp[key])

    for i in range(len(vuln)-1):
        name.append("")
        date.append("")
            

    df= pd.DataFrame({"Name": name, "Date": date, "Vulnerability": vuln,"Detail":detail,"Remediation":remediation })

    df.to_csv('report_vuln.csv', encoding='utf-8-sig')

    return send_file(
        'report_vuln.csv',
        mimetype='text/csv',
        download_name=f'{name[0]}.csv',
        as_attachment=True
    )

  
@app.route('/delete_photo/<string:file_tmp>', methods=['GET'])
def delete_photo(file_tmp):

    
    if request.method == 'GET':
       
        os.remove(str(app.config['UPLOAD_PATH'])+"/"+file_tmp) 


@app.route('/upload_photo/<int:id>', methods=['GET','POST'])
def upload_photo(id):


    id = str(id)

    if request.method == 'POST':
        uploaded_file = request.files['file']
        filename = secure_filename(uploaded_file.filename)

        if int(id) !=0:
            id=int(id)-1
            id=str(id)
            modified_name = "{}_{}".format(id,filename)
            id=int(id)+1
            id=str(id)
        else:
            id=str(id)
            modified_name = "{}_{}".format(id,filename)
            

       
        if filename != '':
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS'] :
                abort(400)
            uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], modified_name))
        return redirect('/upload_photo/'+id)

    if request.method == 'GET':
        return render_template("updatephoto.html",id=id)





@app.route('/report',methods=['GET'])
def report():


    cr = []
    mydb = mysql.connector.connect(**config)

    mycursor = mydb.cursor()

   
    mycursor.execute("SELECT * FROM report order by vulnerability")

    for row in mycursor.fetchall():
            cr.append({"id": row[0], "vulnerability": row[1], "remediation": row[2]})


   

    files = glob.glob(str(app.config['UPLOAD_PATH'])+"/*.png", recursive=True)

    for f in files:
        try:
            os.remove(f)
        except OSError as e:
            print("Error: %s : %s" % (f, e.strerror))

        
        
    return render_template("report.html", vulnList = cr , vulnItem="---", id=str(0))




@app.route('/update_dropdown/<int:id>',methods=['GET'])
def get_update_dropdown(id):

    

    if request.method == 'GET':
    

        id = str(id)


        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()


        if request.method == 'GET':
            mycursor.execute("SELECT * FROM report WHERE id = %s", (id,))

            for row in mycursor.fetchall():
                    cr= row[3]
                    cr_vuln = row[2]
                    cr_name = row[1]
                    cr_reference = row[4]
                

        
            vuln= jsonify({ "id": str(cr), "detail": str(cr_vuln), "name": str(cr_name), "reference": str(cr_reference)})

            return vuln





@app.route('/update_dropdown/',methods=['POST'])
def update_dropdown():

        # select = request.args.to_dict()
        select = request.form.to_dict()
        # return jsonify({ "vuln": str(select) })

        op = request.form["op"]

        # return str(select)
        select = str(select)
        # my_dict_json = json.loads(select)

        # my_dict=json.loads(select.replace("\'", "\""))

        my_dict = urllib.parse.quote(select, safe='')

        # return redirect(url_for('get_csv', my_dict=my_dict))

        if op == "Generate CSV":
            return redirect(url_for('get_csv', my_dict=my_dict))
        else:
            return redirect(url_for('get_excel', my_dict=my_dict))

        # return my_dict



def parseCSV(filePath):
    
    col_names = ['vulnerability','detail','remediation', 'reference']
    
    csvData = pd.read_csv(filePath,names=col_names, header=None, delimiter = ';',skiprows=1)
            
    for i,row in csvData.iterrows():
                    sql = "INSERT INTO report (vulnerability, detail, remediation, reference) VALUES (%s, %s, %s, %s)"
                    value = (row['vulnerability'],row['detail'],row['remediation'],row['reference'])

                    mydb = mysql.connector.connect(**config)

                    mycursor = mydb.cursor()

                    mycursor.execute(sql, value)
                    mydb.commit()
                
                    print(i,row['vulnerability'],row['detail'],row['remediation'],row['reference'])


@app.route("/", methods = ['POST'])
def addvuln():
    
    if request.method == 'POST':
       
        vuln = request.form["vulnerability"]
        detail = request.form["detail"]
        remediation = request.form["remediation"]
        reference = request.form["reference"]

        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
      
        mycursor.execute("INSERT INTO report (vulnerability,detail,remediation,reference) VALUES (%s, %s, %s, %s)",(vuln,detail,remediation,reference))
        mydb.commit()
        
        return render_template('index.html')


@app.route('/update/<int:id>',methods = ['GET','POST'])
def update(id):
    cr = []
    mydb = mysql.connector.connect(**config)

    mycursor = mydb.cursor()

    if request.method == 'GET':
        mycursor.execute("SELECT * FROM report WHERE id = %s", (id,))
        for row in mycursor.fetchall():
            cr.append({"id": row[0], "vulnerability": escape(row[1]),"detail": escape(row[2]) ,"remediation": escape(row[3]),"reference": escape(row[4])})
        
        return render_template("updatelist.html", vuln = cr[0])

    if request.method == 'POST':

        vuln = request.form["vulnerability"]
        detail = request.form["detail"]
        remediation = request.form["remediation"]
        reference = request.form["reference"]


        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
      
        mycursor.execute("UPDATE report SET vulnerability = %s,detail = %s ,remediation = %s,reference = %s WHERE id = %s", (vuln,detail, remediation,reference,id,))
        mydb.commit()

       
        
        return redirect('/dblist')


@app.route('/delete/<int:id>')
def delete(id):
    mydb = mysql.connector.connect(**config)
    mycursor = mydb.cursor()

    mycursor.execute("DELETE FROM report WHERE id = %s", (id,))
    mydb.commit()
    
    return redirect('/dblist')


@app.route('/dblist')
def dblist():


    cr = []
    mydb = mysql.connector.connect(**config)

    mycursor = mydb.cursor()


    if request.method == 'GET':
        mycursor.execute("SELECT * FROM report")

        for row in mycursor.fetchall():
            cr.append({"id": row[0], "vulnerability": escape(row[1]), "detail": escape(row[2]),"remediation": escape(row[3]),"reference": escape(row[4])})
        
        return render_template("updateindex.html", vulns = cr)





@app.route("/upload", methods=['POST'])
def uploadFiles():

    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS'] :
            abort(400)

        file_path = os.path.join(app.config['UPLOAD_PATH'], filename)
        uploaded_file.save(file_path)
        parseCSV(file_path)
    return redirect(url_for('index'))




@app.route("/", methods=['GET','POST'])
def index():

    if request.method == 'GET':
    
        return render_template('index.html')

    if request.method == 'POST':

        addvuln()
        uploadFiles()


@app.route("/get_excel/<my_dict>",methods=['GET'])
def get_excel(my_dict):


    my_dict = urllib.parse.unquote(my_dict)
   
    
    my_dict = my_dict.replace('document.cookie = "ActionID=" + actionsArray[value] + "; expires=" + date.toUTCString() + "; path=/myApp/" + "; secure;" ' ,"document.cookie = 'ActionID=' + actionsArray[value] + '; expires=' + date.toUTCString() + '; path=/myApp/' + '; secure;' ")
    my_dict = my_dict.replace("Request['value']","Request['value']")
    my_dict = my_dict.replace('referer = Request.UrlReferrer != null ? Request.UrlReferrer.ToString() : "None"' ,"referer = Request.UrlReferrer != null ? Request.UrlReferrer.ToString() : 'None'")
    my_dict = my_dict.replace('builder["Persist Security Info"] = "False"' ,"builder['Persist Security Info'] = 'False'")
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
        .replace(' casewhenv_risk="RISK"then"Y"else"N" ' ," casewhenv_risk='RISK'then'Y'else'N' ") \
        .replace('"Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled"' ,"'Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled'") \
        .replace('builder["Persist Security Info"] = "False"' ,"builder['Persist Security Info'] = 'False'") \
        .replace('"Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled; Encrypt=true; TrustServerCertificate=true"' ,"'Data Source=server63; Initial Catalog=Clinic; Integrated Security=true; Column Encryption Setting=enabled; Encrypt=true; TrustServerCertificate=true'") \
        .replace('''Request')('"value"')')''' ,"(Request[param])") \
        .replace('''"None"''' ,"'None'") \
        .replace('''"true"''' ,"'true'") \
        .replace('''"param"''' ,"'param'") \
        .replace('''app.config')('"SESSION_COOKIE_SECURE "')') = True''' ,"app.config['SESSION_COOKIE_SECURE '] = True") \
        .replace('''// Data is stored in DOM, but not persistently ')')''' ,"// Data is stored in DOM, but not persistently }") \
        .replace('''document.cookie = "ActionID=" + actionsArray')('value')') + "; expires=" + date.toUTCString() + "; path=/myApp/" + "; secure;"''' , "document.cookie = 'ActionID=' + actionsArray')('value')') + '; expires=' + date.toUTCString() + '; path=/myApp/' + '; secure;'")
     

    

    with open("data.json", "w") as text_file:
        text_file.write(my_dict)


    with open('data.json', encoding='utf-8') as f:
        excel_tmp = json.loads(f.read().encode('utf-8').decode())


    os.remove("data.json") 
   
    

    comp=[]
    name=[]
    date=[]
    vuln=[]
    detail=[]
    remediation=[]
    classify=[]
    reference=[]
    high=[]
    medium=[]
    critical=[]
    tool=[]
    url=[]
    quantity=[]

    for key in excel_tmp.keys():
        if key.startswith('name'):
            name.append(excel_tmp[key])
        if key.startswith('comp'):
            comp.append(excel_tmp[key])
        if key.startswith('date'):
            date.append(excel_tmp[key])
        if ('vuln') in key:
            vuln.append(excel_tmp[key])
        if ('detail') in key:
            detail.append(excel_tmp[key])
        if ('remediation') in key:
            remediation.append(excel_tmp[key])
        if ('reference') in key:
            reference.append(excel_tmp[key])
        if ('fname_class') in key:
            classify.append(excel_tmp[key])
        if ('hig') in key:
            high.append(excel_tmp[key])
        if ('med') in key:
            medium.append(excel_tmp[key])
        if ('critical') in key:
            critical.append(excel_tmp[key])
        if ('fname_tool') in key:
            tool.append(excel_tmp[key])
        if ('url') in key:
            url.append(excel_tmp[key])
        if ('qtd') in key:
            quantity.append(excel_tmp[key])

    for i in range(len(vuln)-1):
        name.append("")
        date.append("")
        high.append("")
        medium.append("")
        tool.append("")
        url.append("")
        critical.append("")
       
    
    df_1= pd.DataFrame({"Name": name, "Date": date, "Vulnerability": vuln,"Detail":detail,"Remediation":remediation,"Criticity":classify,"Quantity":quantity,"Reference":reference })


    # #create an output stream
    output = BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')

    #taken from the original question
    df_1.to_excel(writer, sheet_name = "Results", startrow=1, header=False)

    workbook = writer.book

    worksheet1 = writer.sheets['Results']
    worksheet1.set_column('C:F', 30)
    


    worksheet1.write('B1', 'Name')
    worksheet1.write('C1', 'Date')
    worksheet1.write('D1', 'Vulnerability')
    worksheet1.write('E1', 'Detail')
    worksheet1.write('F1', 'Remediation')
    worksheet1.write('G1', 'Criticity')
    worksheet1.write('H1', 'Quantity')
    worksheet1.write('I1', 'Reference')

    header_format1 = workbook.add_format({'bg_color': '#FFE100','bold': True})

    format0 = workbook.add_format({'bg_color': '#C7A4D3',
                               'font_color': '#62177C'})

    format1 = workbook.add_format({'bg_color': '#FFC7CE',
                               'font_color': '#9C0006'})

    format2 = workbook.add_format({'bg_color': '#C6EFCE',
                               'font_color': '#006100'})

    format3 = workbook.add_format({'bg_color': '#87CEFA',
                               'font_color': '#0000CD'})
    
    format4 = workbook.add_format({'text_wrap': True})
    format5 = workbook.add_format({'border': 2})

    wrap = workbook.add_format({'text_wrap': True})

    hyper_link = workbook.add_format({'font_color': 'blue', 'underline':  1,'text_wrap': True})

    worksheet1.set_column('B:F',cell_format=wrap)

    # worksheet1.hide_gridlines(2)


    worksheet1.set_row(0,40, cell_format=header_format1)
    worksheet1.set_column('E:F', cell_format=format4)
    dir_list = os.listdir("icon")
    worksheet1.insert_image('A1',"icon/"+str(dir_list[0]),{'object_position': 4})


    worksheet1.conditional_format('G2:G100', {'type': 'formula',
                                         'criteria': 'G2:G100="Critical"',
                                         'format': format0})

    worksheet1.conditional_format('G2:G100', {'type': 'formula',
                                         'criteria': 'G2:G100="High"',
                                         'format': format1})
    
    worksheet1.conditional_format('G2:G100', {'type': 'formula',
                                         'criteria': 'G2:G100="Low"',
                                         'format': format2})

    worksheet1.conditional_format('G2:G100', {'type': 'formula',
                                         'criteria': 'G2:G100="Medium"',
                                         'format': format3})



    dir_list = os.listdir(app.config['UPLOAD_PATH'])

    # return str(dir_list[::-1])
    # worksheet.write_url('A1', 'internal:Sheet2!A1', string="Link to sheet2", tip="Click here")

    item = 0
    for x in sorted(dir_list[::-1]):

            
            
            if item == 0:
                worksheet = workbook.add_worksheet("False Positive")
                worksheet.set_row(0, cell_format=header_format1)
                worksheet.write('A1', f"{tool[0]} TOOL ",header_format1)
                worksheet.write('A2', f"URL: {url[0]}")
                worksheet.write('A3', f"Foram tratadas {critical[0]} vulnerabilidades críticas, {high[0]} vulnerabilidades altas e {medium[0]} vulnerabilidades médias")
    
                worksheet.insert_image('B8',str(app.config['UPLOAD_PATH'])+"/"+x)

            else:
                id_vuln= int(x.split('_')[0])
                # id_vuln=id_vuln-1
              
                worksheet = workbook.add_worksheet(f"{x}")
                worksheet.set_row(0, cell_format=header_format1)
                #worksheet.write('A1', f"ID Vulnerabilidade {str(id_vuln)}")
                worksheet.insert_image('B4',str(app.config['UPLOAD_PATH'])+"/"+x)
                worksheet.write_url(f'A1', f'internal:Results!D{id_vuln+2}',string=f"ID Vulnerabilidade {str(id_vuln)}",cell_format=header_format1)
                worksheet1.write_url(f'D{id_vuln+2}', f"internal:'{x}'!A1",string=vuln[id_vuln],cell_format=hyper_link)

            worksheet.hide_gridlines(2)

            item+=1

            
    
    

    writer.save() 
                            

    #the writer has done its job
    writer.close()

    #go back to the beginning of the stream
    output.seek(0)

    #finally return the file
    return send_file(output, attachment_filename= f"{name[0]}_{tool[0]}.xlsx", as_attachment=True)


@app.route('/home')
def home():
    return render_template('home.html')

      


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug = True)
    # app.run(host='0.0.0.0')
