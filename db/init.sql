CREATE DATABASE sec;
use sec;


CREATE TABLE report (
	  id int(11) NOT NULL AUTO_INCREMENT ,
  	vulnerability VARCHAR(255) NOT NULL,
  	remediation VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO report (id,vulnerability, remediation) VALUES (1, 'xss', 'Usar CSP, headers e evitar caracteres especiais');




