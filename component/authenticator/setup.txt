Steps to run

1.  Build the org.wso2.carbon.identity.application.authentication.endpoint and copy the authenticationendpoint.war 
    to <IS-HOME>/repository/deployment/server/webapps/authenticationendpoint
    Or unzip the authenticationendpoint.war & copy the smsotp.jsp from smsotp/org.wso2.carbon.identity.authenticator/src/main/resources 
    to <IS-HOME>/repository/deployment/server/webapps/authenticationendpoint

2.  Build the org.wso2.carbon.identity.authenticator & copy the org.wso2.carbon.identity.authenticator.SMSOTP-1.0.0.jar 
    to <IS-HOME>/repository/components/dropins

3.  Follow the steps in https://docs.wso2.com/pages/viewpage.action?title=SMSOTP%2BAuthenticator&spaceKey=ISCONNECTORS