
from crypt import methods
import re
from flask import Flask, request, redirect, url_for,render_template,jsonify,abort,send_from_directory,Response
import json
from flask_mysqldb import MySQL
import mysql.connector
import os
import pandas as pd
from werkzeug.utils import secure_filename
import csv


app = Flask(__name__)

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



@app.route("/get_csv")
def get_csv():
    # csv = '1,2,3\n4,5,6\n'
    # my_dict_vuln = update_dropdown()

    # my_dict_str= my_dict_vuln.json()
    r = request.post('http://db:5000/update_dropdown')

    my_dict = r.json()


    with open('report_vuln.csv', 'w') as f:  
        w = csv.DictWriter(f, my_dict.keys())
        w.writeheader()
        w.writerow(my_dict)

        return Response(
            csv,
            mimetype="text/csv",
            headers={"Content-disposition":
                    "attachment; filename=report_vuln.csv"})




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
                

        
            vuln= jsonify({ "id": str(cr), "detail": str(cr_vuln)})

            return vuln





@app.route('/update_dropdown/',methods=['POST'])
def update_dropdown():


        select = request.form.to_dict()
        return jsonify({ "vuln": str(select) })

        # my_dict_vuln = jsonify({ "vuln": str(select) })

        # print(my_dict_vuln)
        

        # get_csv(jsonify({ "vuln": str(select) }))


            

   

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
            cr.append({"id": row[0], "vulnerability": row[1],"detail": row[2] ,"remediation": row[3]})
        
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
            cr.append({"id": row[0], "vulnerability": row[1], "detail": row[2],"remediation": row[3]})
        
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
