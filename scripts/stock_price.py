#!/usr/bin/env python3

# Check the price of a given stock at Yahoo finance

# ex: python ./stock_price.py AAPL

import argparse
import sys

import yfinance as yf


def main():
    parser = argparse.ArgumentParser(description="Show a recent stock price.")
    parser.add_argument("ticker", help="Stock ticker, such as AAPL or MSFT")
    args = parser.parse_args()

    try:
        history = yf.Ticker(args.ticker.upper()).history(period="5d")
        if history.empty:
            raise ValueError("No price data found. Check the ticker symbol.")

        latest = history.dropna(subset=["Close"]).iloc[-1]
        date = history.dropna(subset=["Close"]).index[-1].date()
        print(f"{args.ticker.upper()} closing price on {date}: {latest['Close']:.2f}")
    except Exception as error:
        print(f"Could not fetch price: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

