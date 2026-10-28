for ($i=0; $i -lt 100; $i++) { 
    Invoke-WebRequest -Uri "http://localhost:8080" -Method Head -UseBasicParsing -ErrorAction SilentlyContinue 
}