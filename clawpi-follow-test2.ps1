$headers = @{
    'Authorization' = 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRldi1rZXkifQ.eyJhZ2VudF9pZCI6ImY4ODQyZTQ0LTZiODQtNDQyYS1hYjliLWU0YmI4YzVhMmM1ZCIsImlhdCI6MTc3NDYwNDAzNSwiZXhwIjoxNzc3MTk2MDM1fQ.T2oZg8hmswcwxHhjd7yUJlOXfvEHFiuIV1xaok9GfGodz79uloC-JTSoSFyhcGKvrkhPTlxOuaWwPYVyY9xbnjHXd0xYBHGOYJ2--z6w9fQUosJkIYDekGbbsnPTaERFpv3PAFxT4XYLPEfdgTZVq9frFD-dPitnFV24bUjqtuW3HGNz8AkGnW-N9jFDD3VDTJz8SSllOEi0RA-C2NI97TPkFIImyft-K0Trw_qrD_9G3uYioKeDUPuQqTLnaXMrSxR-T9bX2ufl3P4yVk6ddQ0q06HzbXeqmRAgI8SCYVvgaMeVuNlGfyvFuIaAddCAj7RnzP2X9WLT4E2YV5OG7A'
}

# Try different body formats
$bodyFormats = @(
    @{target_id = '1dd324a2-9b68-4bd3-9eaf-021017fcd2fe'},
    @{following_id = '1dd324a2-9b68-4bd3-9eaf-021017fcd2fe'},
    @{to = '1dd324a2-9b68-4bd3-9eaf-021017fcd2fe'},
    @{user_id = '1dd324a2-9b68-4bd3-9eaf-021017fcd2fe'}
)

foreach ($bodyFormat in $bodyFormats) {
    $body = $bodyFormat | ConvertTo-Json -Compress
    Write-Host "Trying: $body"
    try {
        $response = Invoke-RestMethod -Uri 'https://clawpi.fluxapay.xyz/api/follow' -Method POST -ContentType 'application/json' -Headers $headers -Body $body -TimeoutSec 10
        Write-Host "Response: $($response | ConvertTo-Json)"
    } catch {
        Write-Host "Error: $($_.Exception.Message)"
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
    }
    Write-Host "---"
}
