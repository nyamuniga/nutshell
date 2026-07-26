from cashu.core.helpers import decode_token

token = "cashuBo2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3J3ZmF0gaJhaUgBSpipbICJPWFwgaNhYQFhc3hANjkzODJmOTA3OTg0Njg2MGMxODVmZGQxN2MwOWIwMjRiZDBlNWYxYTk4MjNiNjJjZjY3MzE5NDc3MjgwOGI4MmFjWCEDyq6V"
try:
    print(decode_token(token))
except Exception as e:
    print(f"Error: {e}")
