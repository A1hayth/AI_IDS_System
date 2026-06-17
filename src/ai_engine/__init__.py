# coding=utf-8
import os
import sys

# 注入动态路径补丁
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from predictor import Detector
except ImportError:
    from .predictor import Detector

__all__ = ["Detector"]