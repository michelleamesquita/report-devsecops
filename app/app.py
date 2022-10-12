

from flask import Flask, request, redirect, url_for,render_template,jsonify,abort,send_from_directory,Response,send_file,escape
import json
from flask_mysqldb import MySQL
import mysql.connector
import os
import pandas as pd
from werkzeug.utils import secure_filename
import urllib.parse
from unicodedata import normalize
import os

app = Flask(__name__)


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

    df.to_csv('report_vuln.csv')

    return send_file(
        'report_vuln.csv',
        mimetype='text/csv',
        download_name=f'{name[0]}.csv',
        as_attachment=True
    )

  

@app.route('/uploads/<filename>')
def upload(filename):
    return send_from_directory(app.config['UPLOAD_PATH'], filename)

@app.route('/upload_photo', methods=['GET','POST'])
def upload_photo():

    if request.method == 'POST':
        uploaded_file = request.files['file']
        filename = secure_filename(uploaded_file.filename)
        if filename != '':
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS'] :
                abort(400)
            uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
        return redirect(url_for('upload_photo'))

    if request.method == 'GET':
        return render_template("updatephoto.html")


@app.route('/report',methods=['GET'])
def report():


    cr = []
    mydb = mysql.connector.connect(**config)

    mycursor = mydb.cursor()

   
    mycursor.execute("SELECT * FROM report")

    for row in mycursor.fetchall():
            cr.append({"id": row[0], "vulnerability": row[1], "remediation": row[2]})
        
        
    return render_template("report.html", vulnList = cr , vulnItem="---")




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
                

        
            vuln= jsonify({ "id": str(cr), "detail": str(cr_vuln), "name": str(cr_name)})

            return vuln





@app.route('/update_dropdown/',methods=['POST'])
def update_dropdown():

        # select = request.args.to_dict()
        select = request.form.to_dict()
        # return jsonify({ "vuln": str(select) })

        # return str(select)
        select = str(select)
        # my_dict_json = json.loads(select)

        # my_dict=json.loads(select.replace("\'", "\""))

        my_dict = urllib.parse.quote(select, safe='')

        return redirect(url_for('get_csv', my_dict=my_dict))

        # return my_dict



def parseCSV(filePath):
    
    col_names = ['vulnerability','detail','remediation']
    
    csvData = pd.read_csv(filePath,names=col_names, header=None, delimiter = ';',skiprows=1)
            
    for i,row in csvData.iterrows():
                    sql = "INSERT INTO report (vulnerability, detail, remediation) VALUES (%s, %s, %s)"
                    value = (row['vulnerability'],row['detail'],row['remediation'])

                    mydb = mysql.connector.connect(**config)

                    mycursor = mydb.cursor()

                    mycursor.execute(sql, value)
                    mydb.commit()
                
                    print(i,row['vulnerability'],row['detail'],row['remediation'])


@app.route("/", methods = ['POST'])
def addvuln():
    
    if request.method == 'POST':
       
        vuln = request.form["vulnerability"]
        detail = request.form["detail"]
        remediation = request.form["remediation"]

        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
      
        mycursor.execute("INSERT INTO report (vulnerability,detail,remediation) VALUES (%s, %s, %s)",(vuln,detail,remediation))
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
            cr.append({"id": row[0], "vulnerability": escape(row[1]),"detail": escape(row[2]) ,"remediation": escape(row[3])})
        
        return render_template("updatelist.html", vuln = cr[0])

    if request.method == 'POST':

        vuln = request.form["vulnerability"]
        detail = request.form["detail"]
        remediation = request.form["remediation"]

        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
      
        mycursor.execute("UPDATE report SET vulnerability = %s,detail = %s ,remediation = %s WHERE id = %s", (vuln,detail, remediation,id,))
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
            cr.append({"id": row[0], "vulnerability": escape(row[1]), "detail": escape(row[2]),"remediation": escape(row[3])})
        
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

 

      


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug = True)
    # app.run(host='0.0.0.0')
