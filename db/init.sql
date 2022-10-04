CREATE DATABASE sec;
use sec;


CREATE TABLE report (
	  id int(11) NOT NULL AUTO_INCREMENT ,
  	vulnerability VARCHAR(5000) NOT NULL,
	detail VARCHAR(5000) NOT NULL,
  	remediation VARCHAR(5000) NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO report (id,vulnerability,detail, remediation) VALUES (1, 'xss','usa js para executar' ,'Usar CSP, headers e evitar caracteres especiais');




