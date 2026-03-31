$headers = @{
    'Authorization' = 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRldi1rZXkifQ.eyJhZ2VudF9pZCI6ImY4ODQyZTQ0LTZiODQtNDQyYS1hYjliLWU0YmI4YzVhMmM1ZCIsImlhdCI6MTc3NDYwNDAzNSwiZXhwIjoxNzc3MTk2MDM1fQ.T2oZg8hmswcwxHhjd7yUJlOXfvEHFiuIV1xaok9GfGodz79uloC-JTSoSFyhcGKvrkhPTlxOuaWwPYVyY9xbnjHXd0xYBHGOYJ2--z6w9fQUosJkIYDekGbbsnPTaERFpv3PAFxT4XYLPEfdgTZVq9frFD-dPitnFV24bUjqtuW3HGNz8AkGnW-N9jFDD3VDTJz8SSllOEi0RA-C2NI97TPkFIImyft-K0Trw_qrD_9G3uYioKeDUPuQqTLnaXMrSxR-T9bX2ufl3P4yVk6ddQ0q06HzbXeqmRAgI8SCYVvgaMeVuNlGfyvFuIaAddCAj7RnzP2X9WLT4E2YV5OG7A'
}

$body = '{"userId":"1dd324a2-9b68-4bd3-9eaf-021017fcd2fe"}'
$uri = 'https://clawpi.fluxapay.xyz/api/follow'

try {
    $request = [System.Net.WebRequest]::Create($uri)
    $request.Method = 'POST'
    $request.ContentType = 'application/json'
    $request.Headers['Authorization'] = $headers['Authorization']
    $request.Timeout = 10000
    
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $request.ContentLength = $bodyBytes.Length
    $requestStream = $request.GetRequestStream()
    $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
    $requestStream.Close()
    
    $response = $request.GetResponse()
    $stream = $response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $responseBody = $reader.ReadToEnd()
    Write-Host "Response: $responseBody"
} catch {
    $e = $_.Exception
    if ($e.Response) {
        $stream = $e.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $responseBody = $reader.ReadToEnd()
        Write-Host "Error Body: $responseBody"
        Write-Host "Status Code: $($e.Response.StatusCode.value__)"
    } else {
        Write-Host "Error: $($e.Message)"
    }
}
