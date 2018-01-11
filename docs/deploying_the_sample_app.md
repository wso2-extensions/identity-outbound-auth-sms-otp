### Deploying the Sample App

This topic provides instructions on how to deploy the sample application (travelocity).

1. You can download the travelocity.com.war file from [here](https://docs.wso2.com/download/attachments/48282788/travelocity.com.war?version=1&modificationDate=1509344588000&api=v2) or you can build the latest travelocity application from [here](https://github.com/wso2/product-is/tree/5.x.x/modules/samples/sso/sso-agent-sample).
2. Deploy this sample web app on a web container.
  * Use the Apache Tomcat server to do this. If you have not downloaded Apache Tomcat already, download it from [here](https://tomcat.apache.org/download-70.cgi).

     ````
     Tip: Since this sample is written based on Servlet 3.0, it needs to be deployed on Tomcat 7.x.
     ````
  * Copy the .war file into the webapps folder. For example, <TOMCAT_HOME>/apache-tomcat-\<version>/webapps.
3. Start the Tomcat server.

To check the sample application, navigate to http://<TOMCAT_HOST>:<TOMCAT_PORT>/travelocity.com/index.jsp on your browser.
For example, http://localhost:8080/travelocity.com/index.jsp.

````
Note: It is recommended that you use a hostname that is not localhost to avoid browser errors. Modify the /etc/hosts entry in your machine to reflect this. Note that localhost is used throughout thisdocumentation as an example, but you must modify this when configuring these authenticators or connectors with this sample application.
````