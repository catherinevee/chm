@echo off
echo  Starting Catalyst Health Monitor (CHM)...
echo.

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo  Docker is not running. 
    echo.
    echo Starting in LOCAL DEVELOPMENT mode...
    echo.
    echo Starting Backend Server...
    start /min python backend\servers\working_server.py
    timeout /t 3 /nobreak >nul
    echo Starting Frontend Application...
    cd frontend
    start /min npm start
    cd ..
    echo.
    echo PASS: CHM Application is starting locally...
    echo  Frontend will be available at: http://localhost:3000
    echo  Backend API available at: http://localhost:8000
    echo.
    echo Press any key to open the application in your browser...
    pause >nul
    start http://localhost:3000
) else (
    echo  Docker is running. Choose deployment mode:
    echo.
    echo 1. Development mode (with hot reloading)
    echo 2. Production mode
    echo 3. Local development (no Docker)
    echo.
    set /p choice="Enter your choice (1-3): "
    
    if "%choice%"=="1" (
        echo  Starting in DEVELOPMENT mode with hot reloading...
        docker-compose -f docker-compose.dev.yml up --build
    ) else if "%choice%"=="2" (
        echo  Starting in PRODUCTION mode...
        docker-compose up --build
    ) else if "%choice%"=="3" (
        echo  Starting in LOCAL DEVELOPMENT mode...
        echo.
        echo Starting Backend Server...
        start /min python backend\servers\working_server.py
        timeout /t 3 /nobreak >nul
        echo Starting Frontend Application...
        cd frontend
        start /min npm start
        cd ..
        echo.
        echo PASS: CHM Application is starting locally...
        echo  Frontend will be available at: http://localhost:3000
        echo  Backend API available at: http://localhost:8000
        echo.
        echo Press any key to open the application in your browser...
        pause >nul
        start http://localhost:3000
    ) else (
        echo  Invalid choice. Starting in LOCAL DEVELOPMENT mode...
        echo.
        echo Starting Backend Server...
        start /min python backend\servers\working_server.py
        timeout /t 3 /nobreak >nul
        echo Starting Frontend Application...
        cd frontend
        start /min npm start
        cd ..
        echo.
        echo PASS: CHM Application is starting locally...
        echo  Frontend will be available at: http://localhost:3000
        echo  Backend API available at: http://localhost:8000
        echo.
        echo Press any key to open the application in your browser...
        pause >nul
        start http://localhost:3000
    )
)
