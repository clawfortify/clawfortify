---
name: weather-forecast
description: Get weather forecasts for any location using the OpenWeather API
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - curl
      env:
        - OPENWEATHER_API_KEY
---

# Weather Forecast

Get current weather and forecasts for any location.

## Usage

```bash
curl "https://api.openweathermap.org/data/2.5/weather?q=${CITY}&appid=${OPENWEATHER_API_KEY}"
```

## Features

- Current weather conditions
- 5-day forecast
- Temperature in Celsius or Fahrenheit
