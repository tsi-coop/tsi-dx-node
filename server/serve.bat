@echo off
setlocal

title TSI Aadhaar Vault Plus
:: Check if .env file exists
if not exist ".env" (
    echo Error: .env file not found. Please create it.
    exit /b 1
)

:: Parse .env file line by line
:: /F "tokens=1* delims==" means:
:: - read each line
:: - "tokens=1*" splits the line at the first '='
::   - token 1 gets the part before '=' (the variable name)
::   - token * gets all the rest of the line (the value), including spaces
:: - "delims==" specifies that '=' is the delimiter
for /f "tokens=1* delims==" %%A in (.env) do (
    :: Check if the line is not empty and not a comment (starts with #)
    if not "%%A"=="" (
        if not "%%A"=="::" (
            if not "%%A"=="#" (
                :: Set the environment variable
                set "%%A=%%B"
            )
        )
    )
)

set JAVA_HOME=%JAVA_HOME%
set TSI_DX_NODE_ENV=%TSI_DX_NODE_ENV%
set TSI_DX_NODE_HOME=%TSI_DX_NODE_HOME%
set POSTGRES_HOST=%POSTGRES_HOST%
set POSTGRES_DB=%POSTGRES_DB%
set POSTGRES_USER=%POSTGRES_USER%
set POSTGRES_PASSWD=%POSTGRES_PASSWD%
set JETTY_HOME=%JETTY_HOME%
set JETTY_BASE=%JETTY_BASE%
copy %TSI_DX_NODE_HOME%\target\tsi_dx_node.war %JETTY_BASE%\webapps\ROOT.war >NUL
java -jar %JETTY_HOME%/start.jar
