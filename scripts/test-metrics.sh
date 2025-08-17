#!/bin/bash

# Vaultwarden Metrics Test Script
# This script tests the metrics endpoint functionality

set -e

# Configuration
VAULTWARDEN_URL="${VAULTWARDEN_URL:-http://localhost:8080}"
METRICS_TOKEN="${METRICS_TOKEN:-}"
METRICS_PATH="/metrics"

echo "🔍 Testing Vaultwarden Metrics Endpoint"
echo "========================================"
echo "URL: ${VAULTWARDEN_URL}${METRICS_PATH}"

# Function to test endpoint with different authentication methods
test_endpoint() {
    local auth_method="$1"
    local auth_header="$2"
    local expected_status="$3"
    
    echo
    echo "Testing ${auth_method}..."
    
    if [ -n "$auth_header" ]; then
        response=$(curl -s -w "%{http_code}" -H "$auth_header" "${VAULTWARDEN_URL}${METRICS_PATH}")
    else
        response=$(curl -s -w "%{http_code}" "${VAULTWARDEN_URL}${METRICS_PATH}")
    fi
    
    # Extract status code (last 3 characters)
    status_code="${response: -3}"
    content="${response%???}"
    
    echo "Status: $status_code"
    
    if [ "$status_code" = "$expected_status" ]; then
        echo "✅ Expected status code $expected_status"
        
        if [ "$status_code" = "200" ]; then
            # Verify it looks like Prometheus metrics
            if echo "$content" | grep -q "^# HELP"; then
                echo "✅ Response contains Prometheus metrics format"
                
                # Count metrics
                metric_count=$(echo "$content" | grep -c "^vaultwarden_" || true)
                echo "📊 Found $metric_count Vaultwarden metrics"
                
                # Show sample metrics
                echo
                echo "Sample metrics:"
                echo "$content" | grep "^vaultwarden_" | head -5
                
            else
                echo "⚠️  Response doesn't look like Prometheus metrics"
            fi
        fi
    else
        echo "❌ Expected status $expected_status, got $status_code"
        if [ ${#content} -lt 200 ]; then
            echo "Response: $content"
        else
            echo "Response (first 200 chars): ${content:0:200}..."
        fi
    fi
}

# Test 1: Check if metrics are enabled (test without auth first)
echo "1. Testing without authentication..."
test_endpoint "No Authentication" "" "401"

# Test 2: Test with Bearer token if provided
if [ -n "$METRICS_TOKEN" ]; then
    echo
    echo "2. Testing with Bearer token..."
    test_endpoint "Bearer Token" "Authorization: Bearer $METRICS_TOKEN" "200"
    
    echo
    echo "3. Testing with query parameter..."
    response=$(curl -s -w "%{http_code}" "${VAULTWARDEN_URL}${METRICS_PATH}?token=${METRICS_TOKEN}")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo "✅ Query parameter authentication works"
    else
        echo "❌ Query parameter authentication failed (status: $status_code)"
    fi
    
    echo
    echo "4. Testing with invalid token..."
    test_endpoint "Invalid Token" "Authorization: Bearer invalid-token" "401"
    
else
    echo
    echo "2. Skipping token tests (METRICS_TOKEN not set)"
    echo "   To test authentication, set METRICS_TOKEN environment variable"
fi

# Test 3: Check alive endpoint (should work regardless of metrics config)
echo
echo "5. Testing /alive endpoint..."
alive_response=$(curl -s -w "%{http_code}" "${VAULTWARDEN_URL}/alive")
alive_status="${alive_response: -3}"

if [ "$alive_status" = "200" ]; then
    echo "✅ /alive endpoint is working"
else
    echo "❌ /alive endpoint failed (status: $alive_status)"
fi

# Test 4: Validate specific metrics exist (if we got a successful response)
if [ -n "$METRICS_TOKEN" ]; then
    echo
    echo "6. Validating specific metrics..."
    
    metrics_response=$(curl -s -H "Authorization: Bearer $METRICS_TOKEN" "${VAULTWARDEN_URL}${METRICS_PATH}")
    
    # List of expected metrics
    expected_metrics=(
        "vaultwarden_uptime_seconds"
        "vaultwarden_build_info"
        "vaultwarden_users_total"
        "vaultwarden_http_requests_total"
        "vaultwarden_db_connections_active"
    )
    
    for metric in "${expected_metrics[@]}"; do
        if echo "$metrics_response" | grep -q "$metric"; then
            echo "✅ Found metric: $metric"
        else
            echo "⚠️  Missing metric: $metric"
        fi
    done
fi

echo
echo "🏁 Metrics test completed!"
echo
echo "Next steps:"
echo "1. Configure Prometheus to scrape ${VAULTWARDEN_URL}${METRICS_PATH}"
echo "2. Set up Grafana dashboards using the provided examples"
echo "3. Configure alerting rules for monitoring"
echo
echo "For more information, see MONITORING.md"