
from flask import Flask, request, redirect, url_for,render_template
from flask_mysqldb import MySQL
import mysql.connector
import os
import pandas as pd



app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'key'
app.config['UPLOAD_FOLDER']= 'src'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SESSION_COOKIE_HTTPONLY'] = False


config = {
        'user': 'root',
        'password': 'root',
        'host': 'db',
        'port': '3306',
        'database': 'sec'
        }

@app.route('/report')
def report():


    cr = []
    mydb = mysql.connector.connect(**config)

    mycursor = mydb.cursor()


    if request.method == 'GET':
        mycursor.execute("SELECT * FROM report")

        for row in mycursor.fetchall():
            cr.append({"id": row[0], "vulnerability": row[1], "remediation": row[2]})
        
        return render_template("report.html", vulnList = cr)


def parseCSV(filePath):
    
      col_names = ['vulnerability','remediation']
      
      csvData = pd.read_csv(filePath,names=col_names, header=None, delimiter = ';',skiprows=1)
    
      for i,row in csvData.iterrows():
             sql = "INSERT INTO report (vulnerability,remediation) VALUES (%s, %s)"
             value = (row['vulnerability'],row['remediation'])

             mydb = mysql.connector.connect(**config)

             mycursor = mydb.cursor()

             mycursor.execute(sql, value)
             mydb.commit()
        
             print(i,row['vulnerability'],row['remediation'])


@app.route("/", methods = ['POST'])
def addvuln():
    
    if request.method == 'POST':
       
        vuln = request.form["vulnerability"]
        remediation = request.form["remediation"]

        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
      
        mycursor.execute("INSERT INTO report (vulnerability,remediation) VALUES (%s, %s)",(vuln,remediation))
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
            cr.append({"id": row[0], "vulnerability": row[1], "remediation": row[2]})
        
        return render_template("updatelist.html", vuln = cr[0])

    if request.method == 'POST':

        vuln = request.form["vulnerability"]
        remediation = request.form["remediation"]

        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
      
        mycursor.execute("UPDATE report SET vulnerability = %s, remediation = %s WHERE id = %s", (vuln, remediation,id,))
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
            cr.append({"id": row[0], "vulnerability": row[1], "remediation": row[2]})
        
        return render_template("updateindex.html", vulns = cr)





@app.route("/", methods=['POST'])
def uploadFiles():
      # get the uploaded file
      uploaded_file = request.files['file']
      if uploaded_file.filename != '':
           file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
          # set the file path
           uploaded_file.save(file_path)
           parseCSV(file_path)
          # save the file

      addvuln()

      return redirect(url_for('index'))


@app.route("/")
def index():
    
    return render_template('index.html')

 

      


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug = True)
    # app.run(host='0.0.0.0')
