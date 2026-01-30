#!/bin/bash

python init_system.py

echo "Starting Log Analyzer Daemon..."
python daemon.py &

echo "Starting API Server..."
python api.py
