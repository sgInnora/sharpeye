#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
行为分析模块 - SharpEye入侵检测系统的行为异常检测组件
此模块实现了对系统行为的分析和异常检测，包括进程、用户、系统资源、文件系统和网络行为。
"""

import os
import time
import json
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Union, Set
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock
import psutil
import scipy.stats as stats
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN

# 导入SharpEye本地模块
from ..utils import ml_utils
from ..utils.reporter import Reporter

# 配置日志
logger = logging.getLogger("sharpeye.behavior_analysis")

class BehaviorAnalyzer:
    """行为分析主类，提供对系统行为的分析和异常检测功能"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化行为分析器
        
        Args:
            config: 配置参数，包含异常检测的阈值和模型参数
        """
        self.config = config or {}
        # 保存最近观察到的行为
        self.recent_observations = {
            'process': deque(maxlen=self.config.get('history_size', 1000)),
            'user': deque(maxlen=self.config.get('history_size', 1000)),
            'system': deque(maxlen=self.config.get('history_size', 500)),
            'file': deque(maxlen=self.config.get('history_size', 2000)),
            'network': deque(maxlen=self.config.get('history_size', 1000))
        }
        
        # 基线数据
        self.baselines = {
            'process': None,
            'user': None, 
            'system': None,
            'file': None,
            'network': None
        }
        
        # 特性缩放器
        self.scalers = {
            'process': StandardScaler(),
            'user': StandardScaler(),
            'system': StandardScaler(),
            'file': StandardScaler(),
            'network': StandardScaler()
        }
        
        # 异常检测模型
        self.models = {
            'process': None,
            'user': None,
            'system': None,
            'file': None,
            'network': None
        }
        
        # 初始化专用分析器
        self.process_analyzer = ProcessBehaviorAnalyzer(self)
        self.user_analyzer = UserBehaviorAnalyzer(self)
        self.system_analyzer = SystemResourceAnalyzer(self)
        self.file_analyzer = FileSystemAnalyzer(self)
        self.network_analyzer = NetworkBehaviorAnalyzer(self)
        
        # 同步锁，确保线程安全
        self.lock = Lock()
        
        # 报告器
        self.reporter = Reporter()
        
        logger.info("行为分析模块初始化完成")
    
    def establish_baseline(self, behavior_type: str, data: List[Dict[str, Any]]) -> None:
        """
        建立特定行为类型的基线
        
        Args:
            behavior_type: 行为类型 ('process', 'user', 'system', 'file', 'network')
            data: 基线数据集
        """
        if not data:
            logger.warning(f"尝试为 {behavior_type} 建立基线，但没有提供数据")
            return
            
        with self.lock:
            logger.info(f"为 {behavior_type} 建立行为基线，数据点数量: {len(data)}")
            
            # 将数据转换为特征矩阵
            features = self._extract_features(behavior_type, data)
            
            if features.size == 0:
                logger.warning(f"无法为 {behavior_type} 提取特征，基线未建立")
                return
                
            # 应用特征缩放
            scaled_features = self.scalers[behavior_type].fit_transform(features)
            
            # 使用隔离森林训练异常检测模型
            self.models[behavior_type] = IsolationForest(
                n_estimators=self.config.get('n_estimators', 100),
                contamination=self.config.get('contamination', 0.05),
                random_state=42
            )
            self.models[behavior_type].fit(scaled_features)
            
            # 存储基线统计信息
            self.baselines[behavior_type] = {
                'mean': np.mean(features, axis=0),
                'std': np.std(features, axis=0),
                'median': np.median(features, axis=0),
                'q1': np.percentile(features, 25, axis=0),
                'q3': np.percentile(features, 75, axis=0),
                'min': np.min(features, axis=0),
                'max': np.max(features, axis=0),
                'timestamp': datetime.now().isoformat(),
                'sample_size': len(data)
            }
            
            logger.info(f"{behavior_type} 基线已建立，基于 {len(data)} 个数据点")
    
    def detect_anomalies(self, behavior_type: str, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        检测特定行为类型的异常
        
        Args:
            behavior_type: 行为类型 ('process', 'user', 'system', 'file', 'network')
            data: 待检测的数据
            
        Returns:
            包含异常信息的列表
        """
        if not data:
            return []
            
        if self.models[behavior_type] is None:
            logger.warning(f"{behavior_type} 模型尚未训练，无法检测异常")
            return []
            
        # 提取特征
        features = self._extract_features(behavior_type, data)
        
        if features.size == 0:
            return []
            
        # 应用特征缩放
        scaled_features = self.scalers[behavior_type].transform(features)
        
        # 预测并获取异常分数
        scores = self.models[behavior_type].decision_function(scaled_features)
        predictions = self.models[behavior_type].predict(scaled_features)
        
        # 处理异常结果
        anomalies = []
        for i, (item, score, pred) in enumerate(zip(data, scores, predictions)):
            if pred == -1:  # 异常
                item_copy = item.copy()
                item_copy['anomaly_score'] = float(score)
                item_copy['severity'] = self._calculate_severity(score)
                item_copy['detection_time'] = datetime.now().isoformat()
                anomalies.append(item_copy)
                
        logger.info(f"在 {len(data)} 个 {behavior_type} 数据点中检测到 {len(anomalies)} 个异常")
        return anomalies
    
    def _extract_features(self, behavior_type: str, data: List[Dict[str, Any]]) -> np.ndarray:
        """根据行为类型从数据中提取特征"""
        if behavior_type == 'process':
            return self.process_analyzer.extract_features(data)
        elif behavior_type == 'user':
            return self.user_analyzer.extract_features(data)
        elif behavior_type == 'system':
            return self.system_analyzer.extract_features(data)
        elif behavior_type == 'file':
            return self.file_analyzer.extract_features(data)
        elif behavior_type == 'network':
            return self.network_analyzer.extract_features(data)
        else:
            logger.error(f"未知的行为类型: {behavior_type}")
            return np.array([])
    
    def _calculate_severity(self, anomaly_score: float) -> str:
        """根据异常分数计算严重性级别"""
        abs_score = abs(anomaly_score)
        if abs_score > 0.8:
            return "严重"
        elif abs_score > 0.6:
            return "高"
        elif abs_score > 0.4:
            return "中"
        else:
            return "低"
    
    def add_observation(self, behavior_type: str, data: Dict[str, Any]) -> None:
        """添加新的行为观察"""
        with self.lock:
            self.recent_observations[behavior_type].append(data)
    
    def save_baseline(self, filepath: str) -> bool:
        """保存当前基线到文件"""
        try:
            with open(filepath, 'w') as f:
                json.dump({
                    k: v for k, v in self.baselines.items() if v is not None
                }, f, indent=2)
            logger.info(f"基线保存到: {filepath}")
            return True
        except Exception as e:
            logger.error(f"保存基线失败: {str(e)}")
            return False
    
    def load_baseline(self, filepath: str) -> bool:
        """从文件加载基线"""
        try:
            with open(filepath, 'r') as f:
                loaded_baselines = json.load(f)
            
            for behavior_type, baseline in loaded_baselines.items():
                if behavior_type in self.baselines:
                    self.baselines[behavior_type] = baseline
            
            logger.info(f"从 {filepath} 加载了基线")
            return True
        except Exception as e:
            logger.error(f"加载基线失败: {str(e)}")
            return False
    
    def generate_report(self, anomalies: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """生成基于检测到的异常的综合报告"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_anomalies": sum(len(anoms) for anoms in anomalies.values()),
                "by_type": {btype: len(anoms) for btype, anoms in anomalies.items()}
            },
            "anomalies": anomalies,
            "severity_counts": {
                "严重": 0,
                "高": 0,
                "中": 0,
                "低": 0
            }
        }
        
        # 计算各严重性级别的数量
        for anomaly_list in anomalies.values():
            for anomaly in anomaly_list:
                severity = anomaly.get('severity', '低')
                report["severity_counts"][severity] = report["severity_counts"].get(severity, 0) + 1
        
        return report
    
    def analyze_all(self) -> Dict[str, Any]:
        """分析所有类型的行为并返回异常报告"""
        anomalies = {}
        
        # 处理每种行为类型
        for behavior_type in self.recent_observations.keys():
            observations = list(self.recent_observations[behavior_type])
            if observations and self.models[behavior_type] is not None:
                detected_anomalies = self.detect_anomalies(behavior_type, observations)
                if detected_anomalies:
                    anomalies[behavior_type] = detected_anomalies
        
        # 生成报告
        report = self.generate_report(anomalies)
        
        # 向报告系统发送警报
        for behavior_type, behavior_anomalies in anomalies.items():
            for anomaly in behavior_anomalies:
                if anomaly.get('severity') in ['严重', '高']:
                    self.reporter.report_security_event(
                        event_type=f"behavior_anomaly_{behavior_type}",
                        details=anomaly,
                        severity=anomaly.get('severity', '高')
                    )
        
        return report


class ProcessBehaviorAnalyzer:
    """进程行为分析器，专门用于分析进程行为异常"""
    
    def __init__(self, parent: BehaviorAnalyzer):
        """
        初始化进程行为分析器
        
        Args:
            parent: 父行为分析器实例
        """
        self.parent = parent
        self.config = parent.config.get('process', {})
        self.process_history = {}  # 追踪进程历史行为
    
    def extract_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """
        从进程数据中提取特征
        
        Args:
            data: 进程数据列表
            
        Returns:
            特征矩阵
        """
        if not data:
            return np.array([])
        
        features = []
        for process in data:
            # 提取基本资源使用特征
            cpu_percent = process.get('cpu_percent', 0)
            memory_percent = process.get('memory_percent', 0)
            io_read = process.get('io_read_bytes', 0)
            io_write = process.get('io_write_bytes', 0)
            num_threads = process.get('num_threads', 1)
            num_fds = process.get('num_fds', 0)
            ctx_switches = process.get('ctx_switches', 0)
            
            # 标准化IO值以防止极端值
            io_read_norm = np.log1p(io_read) if io_read > 0 else 0
            io_write_norm = np.log1p(io_write) if io_write > 0 else 0
            
            # 计算进程运行时间（小时）
            create_time = process.get('create_time', time.time())
            run_time_hours = (time.time() - create_time) / 3600
            
            # 网络连接数量
            num_connections = len(process.get('connections', []))
            
            # 命令行参数数量
            cmdline = process.get('cmdline', [])
            num_args = len(cmdline) - 1 if len(cmdline) > 0 else 0
            
            # 子进程数量
            num_children = len(process.get('children', []))
            
            # 用户ID的数字表示
            username = process.get('username', 'unknown')
            # 简单哈希来转换为数值特征
            username_hash = hash(username) % 1000
            
            # 进程行为模式特征
            is_service = 1 if process.get('is_service', False) else 0
            is_daemon = 1 if process.get('is_daemon', False) else 0
            
            # 组合特征向量
            feature_vector = [
                cpu_percent, 
                memory_percent,
                io_read_norm,
                io_write_norm,
                num_threads,
                num_fds,
                ctx_switches,
                run_time_hours,
                num_connections,
                num_args,
                num_children,
                username_hash,
                is_service,
                is_daemon
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def get_process_data(self, pid: int = None) -> Dict[str, Any]:
        """获取单个进程的详细数据"""
        try:
            if pid is None:
                processes_data = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes_data.append(self._get_full_process_info(proc))
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                return processes_data
            else:
                proc = psutil.Process(pid)
                return self._get_full_process_info(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.error(f"获取进程数据错误: {str(e)}")
            return {}
    
    def _get_full_process_info(self, proc: psutil.Process) -> Dict[str, Any]:
        """获取进程的详细信息"""
        try:
            with proc.oneshot():
                info = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'cmdline': proc.cmdline(),
                    'create_time': proc.create_time(),
                    'status': proc.status(),
                    'username': proc.username(),
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'num_threads': proc.num_threads(),
                    'io_counters': None,
                    'connections': [],
                    'is_service': False,
                    'is_daemon': False,
                    'cwd': proc.cwd(),
                    'nice': proc.nice(),
                    'cpu_times': None,
                    'memory_info': None,
                    'children': []
                }
                
                # 尝试获取可能会引发异常的信息
                try:
                    info['io_counters'] = proc.io_counters()._asdict() if proc.io_counters() else None
                except (psutil.AccessDenied, AttributeError):
                    pass
                
                try:
                    info['connections'] = [conn._asdict() for conn in proc.connections()]
                except (psutil.AccessDenied, AttributeError):
                    pass
                
                try:
                    info['cpu_times'] = proc.cpu_times()._asdict()
                except (psutil.AccessDenied, AttributeError):
                    pass
                
                try:
                    info['memory_info'] = proc.memory_info()._asdict()
                except (psutil.AccessDenied, AttributeError):
                    pass
                
                try:
                    info['children'] = [child.pid for child in proc.children()]
                except (psutil.AccessDenied, AttributeError):
                    pass
                
                return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {}
    
    def analyze_process(self, process_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析单个进程数据，返回异常分析结果"""
        # 添加到观察集合
        self.parent.add_observation('process', process_data)
        
        # 如果没有模型，则返回空结果
        if self.parent.models['process'] is None:
            return {}
        
        # 提取特征并检测异常
        features = self.extract_features([process_data])
        
        if features.size == 0:
            return {}
        
        # 应用特征缩放
        scaled_features = self.parent.scalers['process'].transform(features)
        
        # 预测并获取异常分数
        score = float(self.parent.models['process'].decision_function(scaled_features)[0])
        prediction = self.parent.models['process'].predict(scaled_features)[0]
        
        # 如果是异常，返回异常信息
        if prediction == -1:
            return {
                'pid': process_data.get('pid'),
                'name': process_data.get('name'),
                'anomaly_score': score,
                'severity': self.parent._calculate_severity(score),
                'detection_time': datetime.now().isoformat(),
                'details': self._generate_anomaly_details(process_data, score)
            }
        
        return {}
    
    def _generate_anomaly_details(self, process_data: Dict[str, Any], score: float) -> Dict[str, Any]:
        """生成进程异常的详细信息"""
        details = {
            'unusual_aspects': [],
            'risk_factors': [],
            'recommendation': ""
        }
        
        # 检查CPU使用异常
        cpu_percent = process_data.get('cpu_percent', 0)
        if cpu_percent > 80:
            details['unusual_aspects'].append(f"CPU使用率异常高 ({cpu_percent}%)")
            details['risk_factors'].append("高CPU使用可能表明计算密集型恶意活动如挖矿或加密操作")
        
        # 检查内存使用异常
        memory_percent = process_data.get('memory_percent', 0)
        if memory_percent > 50:
            details['unusual_aspects'].append(f"内存使用率异常高 ({memory_percent}%)")
            details['risk_factors'].append("高内存使用可能表明内存驻留恶意软件或数据窃取缓存")
        
        # 检查网络连接数量
        connections = process_data.get('connections', [])
        if len(connections) > 10:
            details['unusual_aspects'].append(f"网络连接数量异常 ({len(connections)})")
            details['risk_factors'].append("大量网络连接可能表明C2通信或数据外泄")
        
        # 检查异常的执行路径
        exe = process_data.get('exe', '')
        if '/tmp/' in exe or '/dev/shm/' in exe:
            details['unusual_aspects'].append(f"可疑执行路径: {exe}")
            details['risk_factors'].append("临时目录中的可执行文件经常被恶意软件使用")
        
        # 添加进程用户
        username = process_data.get('username', '')
        if username == 'root' and not process_data.get('name', '') in ['systemd', 'init', 'kernel']:
            details['unusual_aspects'].append(f"以root用户运行的非系统进程")
            details['risk_factors'].append("权限提升或恶意软件尝试获取系统控制")
        
        # 运行时间异常
        create_time = process_data.get('create_time', time.time())
        run_time_hours = (time.time() - create_time) / 3600
        if run_time_hours < 0.1 and abs(score) > 0.7:  # 新进程且异常分数高
            details['unusual_aspects'].append(f"新创建的异常进程 (运行时间: {run_time_hours:.2f}小时)")
            details['risk_factors'].append("新创建进程表现异常可能表明刚刚执行的恶意代码")
        
        # 基于发现的异常提供建议
        if len(details['unusual_aspects']) > 0:
            name = process_data.get('name', 'unknown')
            pid = process_data.get('pid', 0)
            details['recommendation'] = f"建议调查进程 {name} (PID: {pid})，检查其活动和来源。"
            if abs(score) > 0.8:
                details['recommendation'] += f" 考虑立即终止此进程并进行深入分析。"
        
        return details


class UserBehaviorAnalyzer:
    """用户行为分析器，专门用于分析用户活动异常"""
    
    def __init__(self, parent: BehaviorAnalyzer):
        """初始化用户行为分析器"""
        self.parent = parent
        self.config = parent.config.get('user', {})
        self.user_profiles = {}  # 用户行为配置文件
    
    def extract_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """从用户活动数据中提取特征"""
        if not data:
            return np.array([])
        
        features = []
        for user_activity in data:
            # 提取登录时间特征（小时）
            login_time = user_activity.get('login_time', 0)
            dt = datetime.fromtimestamp(login_time)
            hour_of_day = dt.hour + dt.minute/60.0
            day_of_week = dt.weekday()  # 0-6, 周一到周日
            
            # 登录持续时间（小时）
            session_duration = user_activity.get('session_duration', 0) / 3600
            
            # 登录源IP是否普通
            is_usual_ip = 1 if user_activity.get('is_usual_ip', True) else 0
            
            # 登录失败次数
            login_failures = user_activity.get('login_failures', 0)
            
            # 权限变更
            privilege_changes = user_activity.get('privilege_changes', 0)
            
            # 命令数量
            command_count = user_activity.get('command_count', 0)
            
            # 远程登录
            is_remote = 1 if user_activity.get('is_remote', False) else 0
            
            # 提权操作
            sudo_count = user_activity.get('sudo_count', 0)
            
            # 访问敏感文件
            sensitive_file_access = user_activity.get('sensitive_file_access', 0)
            
            # 组合特征向量
            feature_vector = [
                hour_of_day,
                day_of_week,
                session_duration,
                is_usual_ip,
                login_failures,
                privilege_changes,
                command_count,
                is_remote,
                sudo_count,
                sensitive_file_access
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def analyze_user_activity(self, username: str, activity_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析用户活动并检测异常"""
        # 确保包含用户名
        activity_data['username'] = username
        
        # 添加到观察集合
        self.parent.add_observation('user', activity_data)
        
        # 如果没有模型，则返回空结果
        if self.parent.models['user'] is None:
            return {}
        
        # 提取特征并检测异常
        features = self.extract_features([activity_data])
        
        if features.size == 0:
            return {}
        
        # 应用特征缩放
        scaled_features = self.parent.scalers['user'].transform(features)
        
        # 预测并获取异常分数
        score = float(self.parent.models['user'].decision_function(scaled_features)[0])
        prediction = self.parent.models['user'].predict(scaled_features)[0]
        
        # 如果是异常，返回异常信息
        if prediction == -1:
            return {
                'username': username,
                'anomaly_score': score,
                'severity': self.parent._calculate_severity(score),
                'detection_time': datetime.now().isoformat(),
                'details': self._generate_anomaly_details(activity_data, score)
            }
        
        return {}
    
    def _generate_anomaly_details(self, activity_data: Dict[str, Any], score: float) -> Dict[str, Any]:
        """生成用户活动异常的详细信息"""
        details = {
            'unusual_aspects': [],
            'risk_factors': [],
            'recommendation': ""
        }
        
        # 检查时间异常（非工作时间登录）
        login_time = activity_data.get('login_time', 0)
        if login_time > 0:
            dt = datetime.fromtimestamp(login_time)
            hour = dt.hour
            if hour >= 22 or hour <= 5:
                details['unusual_aspects'].append(f"非工作时间登录 ({dt.strftime('%H:%M')})")
                details['risk_factors'].append("非标准时间的访问可能表明未授权活动")
        
        # 检查异常的源IP
        if not activity_data.get('is_usual_ip', True):
            ip = activity_data.get('source_ip', 'unknown')
            details['unusual_aspects'].append(f"来自非常见IP地址的登录: {ip}")
            details['risk_factors'].append("非常见位置登录可能表明账户被盗用")
        
        # 检查登录失败次数
        login_failures = activity_data.get('login_failures', 0)
        if login_failures > 3:
            details['unusual_aspects'].append(f"多次登录失败尝试 ({login_failures}次)")
            details['risk_factors'].append("多次登录失败表明可能的暴力破解尝试")
        
        # 检查权限变更
        privilege_changes = activity_data.get('privilege_changes', 0)
        if privilege_changes > 0:
            details['unusual_aspects'].append(f"用户权限变更 ({privilege_changes}次)")
            details['risk_factors'].append("权限变更可能表明提权尝试或账户滥用")
        
        # 检查sudo使用异常
        sudo_count = activity_data.get('sudo_count', 0)
        if sudo_count > 10:
            details['unusual_aspects'].append(f"频繁使用sudo命令 ({sudo_count}次)")
            details['risk_factors'].append("大量sudo请求可能表明权限提升尝试")
        
        # 检查敏感文件访问
        sensitive_file_access = activity_data.get('sensitive_file_access', 0)
        if sensitive_file_access > 5:
            details['unusual_aspects'].append(f"频繁访问敏感文件 ({sensitive_file_access}次)")
            details['risk_factors'].append("访问敏感文件可能表明数据泄露尝试")
        
        # 基于发现的异常提供建议
        if len(details['unusual_aspects']) > 0:
            username = activity_data.get('username', 'unknown')
            details['recommendation'] = f"建议调查用户 {username} 的活动，检查可能的账户盗用或滥用。"
            if abs(score) > 0.8:
                details['recommendation'] += f" 考虑临时锁定账户并要求重新身份验证。"
        
        return details


class SystemResourceAnalyzer:
    """系统资源分析器，用于分析系统资源使用异常"""
    
    def __init__(self, parent: BehaviorAnalyzer):
        """初始化系统资源分析器"""
        self.parent = parent
        self.config = parent.config.get('system', {})
        self.resource_history = deque(maxlen=1000)  # 资源使用历史
    
    def extract_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """从系统资源数据中提取特征"""
        if not data:
            return np.array([])
        
        features = []
        for resource_data in data:
            # CPU使用率（所有核心的平均值）
            cpu_percent = resource_data.get('cpu_percent', 0)
            
            # 内存使用率
            memory_percent = resource_data.get('memory_percent', 0)
            
            # 内存可用量（GB）
            memory_available = resource_data.get('memory_available', 0) / (1024**3)
            
            # 虚拟内存使用率
            swap_percent = resource_data.get('swap_percent', 0)
            
            # 磁盘使用率
            disk_usage = resource_data.get('disk_usage', {})
            disk_percent = np.mean([v.get('percent', 0) for v in disk_usage.values()]) if disk_usage else 0
            
            # IO等待率
            io_wait = resource_data.get('io_wait', 0)
            
            # 系统负载（5分钟平均）
            load_5min = resource_data.get('load_avg', [0, 0, 0])[1]
            
            # 网络流量（速率，MB/s）
            net_sent = resource_data.get('net_sent', 0) / (1024**2)
            net_recv = resource_data.get('net_recv', 0) / (1024**2)
            
            # 打开文件数量
            open_files = resource_data.get('open_files', 0)
            
            # 进程总数
            process_count = resource_data.get('process_count', 0)
            
            # 系统温度（如果有）
            temperature = resource_data.get('temperature', 0)
            
            # 组合特征向量
            feature_vector = [
                cpu_percent,
                memory_percent,
                memory_available,
                swap_percent,
                disk_percent,
                io_wait,
                load_5min,
                net_sent,
                net_recv,
                open_files,
                process_count,
                temperature
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def get_system_data(self) -> Dict[str, Any]:
        """收集当前系统资源使用状况"""
        try:
            data = {
                'timestamp': time.time(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'per_cpu_percent': psutil.cpu_percent(interval=1, percpu=True),
                'memory_percent': psutil.virtual_memory().percent,
                'memory_available': psutil.virtual_memory().available,
                'swap_percent': psutil.swap_memory().percent,
                'disk_usage': {},
                'io_wait': 0,  # 需要从/proc/stat解析
                'load_avg': os.getloadavg(),
                'net_sent': 0,  # 需要计算增量
                'net_recv': 0,  # 需要计算增量
                'open_files': len(psutil.Process().open_files()),
                'process_count': len(psutil.pids()),
                'temperature': 0,  # 可能需要特定于平台的方法
                'boot_time': psutil.boot_time()
            }
            
            # 获取磁盘使用情况
            for part in psutil.disk_partitions(all=False):
                if part.fstype:
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        data['disk_usage'][part.mountpoint] = {
                            'total': usage.total,
                            'used': usage.used,
                            'free': usage.free,
                            'percent': usage.percent
                        }
                    except PermissionError:
                        continue
            
            # 获取IO等待信息（Linux专用）
            if os.path.exists('/proc/stat'):
                try:
                    with open('/proc/stat', 'r') as f:
                        for line in f:
                            if line.startswith('cpu '):
                                fields = line.strip().split()
                                if len(fields) >= 8:
                                    # 索引5是iowait时间
                                    total_time = sum(float(x) for x in fields[1:8])
                                    iowait_time = float(fields[5])
                                    data['io_wait'] = (iowait_time / total_time) * 100 if total_time > 0 else 0
                                break
                except:
                    pass
            
            # 添加到历史记录
            self.resource_history.append(data)
            
            # 如果有足够的历史记录，计算网络流量
            if len(self.resource_history) >= 2:
                prev_data = self.resource_history[-2]
                curr_data = self.resource_history[-1]
                
                time_diff = curr_data['timestamp'] - prev_data['timestamp']
                if time_diff > 0:
                    # 获取网络计数器
                    prev_net = psutil.net_io_counters()
                    time.sleep(0.1)  # 短暂等待以获取差值
                    curr_net = psutil.net_io_counters()
                    
                    # 计算网络速率
                    data['net_sent'] = (curr_net.bytes_sent - prev_net.bytes_sent) / time_diff
                    data['net_recv'] = (curr_net.bytes_recv - prev_net.bytes_recv) / time_diff
            
            # 添加到父分析器的观察列表
            self.parent.add_observation('system', data)
            
            return data
        except Exception as e:
            logger.error(f"获取系统资源数据错误: {str(e)}")
            return {}
    
    def analyze_system_resources(self) -> Dict[str, Any]:
        """分析系统资源使用并检测异常"""
        # 获取当前系统数据
        system_data = self.get_system_data()
        if not system_data:
            return {}
        
        # 如果没有模型，则返回空结果
        if self.parent.models['system'] is None:
            return {}
        
        # 提取特征并检测异常
        features = self.extract_features([system_data])
        
        if features.size == 0:
            return {}
        
        # 应用特征缩放
        scaled_features = self.parent.scalers['system'].transform(features)
        
        # 预测并获取异常分数
        score = float(self.parent.models['system'].decision_function(scaled_features)[0])
        prediction = self.parent.models['system'].predict(scaled_features)[0]
        
        # 如果是异常，返回异常信息
        if prediction == -1:
            return {
                'anomaly_score': score,
                'severity': self.parent._calculate_severity(score),
                'detection_time': datetime.now().isoformat(),
                'system_data': system_data,
                'details': self._generate_anomaly_details(system_data, score)
            }
        
        return {}
    
    def _generate_anomaly_details(self, system_data: Dict[str, Any], score: float) -> Dict[str, Any]:
        """生成系统资源异常的详细信息"""
        details = {
            'unusual_aspects': [],
            'risk_factors': [],
            'recommendation': ""
        }
        
        # 检查CPU使用异常
        cpu_percent = system_data.get('cpu_percent', 0)
        if cpu_percent > 90:
            details['unusual_aspects'].append(f"CPU使用率异常高 ({cpu_percent}%)")
            details['risk_factors'].append("高CPU使用可能表明计算密集型恶意活动如挖矿")
        
        # 检查内存使用异常
        memory_percent = system_data.get('memory_percent', 0)
        if memory_percent > 95:
            details['unusual_aspects'].append(f"内存使用率异常高 ({memory_percent}%)")
            details['risk_factors'].append("高内存使用可能表明内存泄漏或资源耗尽攻击")
        
        # 检查交换空间使用异常
        swap_percent = system_data.get('swap_percent', 0)
        if swap_percent > 80:
            details['unusual_aspects'].append(f"交换空间使用率高 ({swap_percent}%)")
            details['risk_factors'].append("高交换空间使用表明系统内存压力")
        
        # 检查IO等待异常
        io_wait = system_data.get('io_wait', 0)
        if io_wait > 30:
            details['unusual_aspects'].append(f"IO等待率高 ({io_wait}%)")
            details['risk_factors'].append("高IO等待可能表明磁盘异常活动或数据导出")
        
        # 检查系统负载异常
        load_avg = system_data.get('load_avg', [0, 0, 0])
        cpu_count = psutil.cpu_count()
        if load_avg[1] > cpu_count * 1.5:  # 5分钟负载超过CPU核心数的1.5倍
            details['unusual_aspects'].append(f"系统负载异常高 ({load_avg[1]})")
            details['risk_factors'].append("高系统负载可能表明异常进程活动")
        
        # 检查网络流量异常
        net_sent = system_data.get('net_sent', 0)
        net_recv = system_data.get('net_recv', 0)
        if net_sent > 50 * 1024 * 1024:  # 50MB/s
            details['unusual_aspects'].append(f"网络发送流量异常高 ({net_sent/(1024*1024):.2f} MB/s)")
            details['risk_factors'].append("大量出站流量可能表明数据外泄")
        if net_recv > 50 * 1024 * 1024:  # 50MB/s
            details['unusual_aspects'].append(f"网络接收流量异常高 ({net_recv/(1024*1024):.2f} MB/s)")
            details['risk_factors'].append("大量入站流量可能表明下载恶意软件或DoS攻击")
        
        # 检查打开文件数量异常
        open_files = system_data.get('open_files', 0)
        if open_files > 1000:
            details['unusual_aspects'].append(f"打开文件数量异常高 ({open_files})")
            details['risk_factors'].append("大量打开文件可能表明文件系统扫描或数据挖掘活动")
        
        # 检查进程数量异常
        process_count = system_data.get('process_count', 0)
        if process_count > 500:
            details['unusual_aspects'].append(f"进程数量异常高 ({process_count})")
            details['risk_factors'].append("大量进程可能表明Fork炸弹或自我复制恶意软件")
        
        # 基于发现的异常提供建议
        if len(details['unusual_aspects']) > 0:
            details['recommendation'] = "建议检查系统资源使用，识别并审核使用资源最多的进程。"
            if abs(score) > 0.8:
                details['recommendation'] += " 考虑立即进行系统层面的安全审计。"
        
        return details


class FileSystemAnalyzer:
    """文件系统分析器，用于分析文件系统活动异常"""
    
    def __init__(self, parent: BehaviorAnalyzer):
        """初始化文件系统分析器"""
        self.parent = parent
        self.config = parent.config.get('file', {})
        self.sensitive_paths = self.config.get('sensitive_paths', [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh', 
            '/var/log', '/root', '/home', '/usr/bin', '/sbin'
        ])
        self.monitored_extensions = self.config.get('monitored_extensions', [
            '.sh', '.py', '.rb', '.pl', '.conf', '.key', '.pem', 
            '.cert', '.db', '.sqlite', '.sql'
        ])
    
    def extract_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """从文件系统活动数据中提取特征"""
        if not data:
            return np.array([])
        
        features = []
        for file_activity in data:
            # 文件操作类型（读=1，写=2，执行=3，删除=4）
            operation_type = file_activity.get('operation_type', 0)
            
            # 文件路径是否敏感
            path = file_activity.get('path', '')
            is_sensitive_path = 0
            for sensitive_path in self.sensitive_paths:
                if path.startswith(sensitive_path):
                    is_sensitive_path = 1
                    break
            
            # 文件扩展名是否受监控
            is_monitored_ext = 0
            file_ext = os.path.splitext(path)[1].lower()
            if file_ext in self.monitored_extensions:
                is_monitored_ext = 1
            
            # 文件大小（MB）
            file_size = file_activity.get('size', 0) / (1024 * 1024)
            
            # 用户ID
            uid = file_activity.get('uid', 0)
            
            # 是否为隐藏文件
            is_hidden = 1 if os.path.basename(path).startswith('.') else 0
            
            # 文件权限
            permissions = file_activity.get('permissions', 0o644)
            is_world_writable = 1 if permissions & 0o002 else 0
            is_suid = 1 if permissions & 0o4000 else 0
            
            # 时间特征
            timestamp = file_activity.get('timestamp', time.time())
            dt = datetime.fromtimestamp(timestamp)
            hour_of_day = dt.hour + dt.minute/60.0
            
            # 操作频率（单位时间内相同文件的操作次数）
            operation_frequency = file_activity.get('operation_frequency', 1)
            
            # 组合特征向量
            feature_vector = [
                operation_type,
                is_sensitive_path,
                is_monitored_ext,
                file_size,
                uid,
                is_hidden,
                is_world_writable,
                is_suid,
                hour_of_day,
                operation_frequency
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def analyze_file_activity(self, file_activity: Dict[str, Any]) -> Dict[str, Any]:
        """分析文件活动并检测异常"""
        # 添加到观察集合
        self.parent.add_observation('file', file_activity)
        
        # 如果没有模型，则返回空结果
        if self.parent.models['file'] is None:
            return {}
        
        # 提取特征并检测异常
        features = self.extract_features([file_activity])
        
        if features.size == 0:
            return {}
        
        # 应用特征缩放
        scaled_features = self.parent.scalers['file'].transform(features)
        
        # 预测并获取异常分数
        score = float(self.parent.models['file'].decision_function(scaled_features)[0])
        prediction = self.parent.models['file'].predict(scaled_features)[0]
        
        # 如果是异常，返回异常信息
        if prediction == -1:
            return {
                'path': file_activity.get('path', ''),
                'anomaly_score': score,
                'severity': self.parent._calculate_severity(score),
                'detection_time': datetime.now().isoformat(),
                'details': self._generate_anomaly_details(file_activity, score)
            }
        
        return {}
    
    def _generate_anomaly_details(self, file_activity: Dict[str, Any], score: float) -> Dict[str, Any]:
        """生成文件活动异常的详细信息"""
        details = {
            'unusual_aspects': [],
            'risk_factors': [],
            'recommendation': ""
        }
        
        path = file_activity.get('path', '')
        operation = file_activity.get('operation', 'unknown')
        operation_type = file_activity.get('operation_type', 0)
        
        # 检查敏感路径访问
        is_sensitive = False
        for sensitive_path in self.sensitive_paths:
            if path.startswith(sensitive_path):
                is_sensitive = True
                details['unusual_aspects'].append(f"访问敏感路径: {path}")
                details['risk_factors'].append("敏感系统文件的改变可能表明系统入侵或配置篡改")
                break
        
        # 检查可执行文件创建/修改
        file_ext = os.path.splitext(path)[1].lower()
        if operation_type == 2 and (path.endswith('.sh') or path.endswith('.py') or path.endswith('.pl') or path.endswith('.rb') or not file_ext):
            details['unusual_aspects'].append(f"创建或修改可执行文件: {path}")
            details['risk_factors'].append("修改脚本或可执行文件可能表明植入后门或木马")
        
        # 检查异常的文件权限
        permissions = file_activity.get('permissions', 0o644)
        if permissions & 0o4000:  # SUID
            details['unusual_aspects'].append(f"设置了SUID权限的文件: {path}")
            details['risk_factors'].append("SUID文件可被利用实现权限提升")
        
        if permissions & 0o2000:  # SGID
            details['unusual_aspects'].append(f"设置了SGID权限的文件: {path}")
            details['risk_factors'].append("SGID文件可被利用实现权限提升")
        
        if permissions & 0o002:  # 全局可写
            details['unusual_aspects'].append(f"全局可写的文件: {path}")
            details['risk_factors'].append("全局可写的文件可被任何用户修改，构成安全风险")
        
        # 检查异常时间的文件活动
        timestamp = file_activity.get('timestamp', time.time())
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        if hour >= 22 or hour <= 5:
            details['unusual_aspects'].append(f"非工作时间的文件活动 ({dt.strftime('%H:%M')})")
            details['risk_factors'].append("非标准时间的文件访问可能表明未授权活动")
        
        # 检查异常的文件大小
        file_size = file_activity.get('size', 0)
        if file_size > 100 * 1024 * 1024 and operation_type in [1, 2]:  # 超过100MB的读/写
            details['unusual_aspects'].append(f"大型文件操作: {file_size/(1024*1024):.2f} MB")
            details['risk_factors'].append("大型文件读写可能表明数据导出或导入")
        
        # 检查隐藏文件
        if os.path.basename(path).startswith('.') and operation_type == 2:
            details['unusual_aspects'].append(f"创建或修改隐藏文件: {path}")
            details['risk_factors'].append("隐藏文件经常被用来隐藏恶意活动")
        
        # 检查临时目录中的可执行文件
        if ('/tmp/' in path or '/dev/shm/' in path) and operation_type == 2:
            details['unusual_aspects'].append(f"在临时目录中创建文件: {path}")
            details['risk_factors'].append("临时目录中的可执行文件经常被恶意软件使用")
        
        # 检查操作频率
        operation_frequency = file_activity.get('operation_frequency', 1)
        if operation_frequency > 10:
            details['unusual_aspects'].append(f"频繁的文件操作 ({operation_frequency}次/分钟)")
            details['risk_factors'].append("频繁的文件操作可能表明自动化脚本或恶意软件活动")
        
        # 基于发现的异常提供建议
        if len(details['unusual_aspects']) > 0:
            details['recommendation'] = f"建议检查文件 {path} 的内容和使用情况。"
            
            if is_sensitive and operation_type == 2:
                details['recommendation'] += " 考虑立即恢复敏感文件的备份并检查系统完整性。"
            elif permissions & 0o4000 or permissions & 0o2000:
                details['recommendation'] += f" 审核文件的权限设置，验证是否有合法理由赋予其SUID/SGID权限。"
                
            if abs(score) > 0.8:
                details['recommendation'] += " 此活动显示为高风险，建议优先调查。"
        
        return details


class NetworkBehaviorAnalyzer:
    """网络行为分析器，用于分析网络流量异常"""
    
    def __init__(self, parent: BehaviorAnalyzer):
        """初始化网络行为分析器"""
        self.parent = parent
        self.config = parent.config.get('network', {})
        self.known_ports = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 
            21: 'FTP', 3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
            53: 'DNS', 123: 'NTP', 161: 'SNMP', 389: 'LDAP', 636: 'LDAPS',
            3389: 'RDP', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            1433: 'MSSQL', 1521: 'Oracle'
        }
        self.connection_stats = defaultdict(lambda: {
            'first_seen': time.time(),
            'last_seen': time.time(),
            'data_sent': 0,
            'data_recv': 0,
            'connections': 0
        })
    
    def extract_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """从网络连接数据中提取特征"""
        if not data:
            return np.array([])
        
        features = []
        for connection_data in data:
            # 连接类型（1=TCP, 2=UDP, 3=其他）
            conn_type = 1 if connection_data.get('protocol', '') == 'tcp' else (2 if connection_data.get('protocol', '') == 'udp' else 3)
            
            # 是否是知名端口
            remote_port = connection_data.get('remote_port', 0)
            is_known_port = 1 if remote_port in self.known_ports else 0
            
            # 远程端口号
            remote_port_norm = np.log1p(remote_port) if remote_port > 0 else 0
            
            # 数据传输量（KB）
            data_sent = connection_data.get('data_sent', 0) / 1024
            data_recv = connection_data.get('data_recv', 0) / 1024
            
            # 连接持续时间（分钟）
            duration = connection_data.get('duration', 0) / 60
            
            # 连接状态（对TCP）
            conn_state = connection_data.get('state', '')
            state_code = 0
            if conn_state == 'ESTABLISHED':
                state_code = 1
            elif conn_state == 'SYN_SENT':
                state_code = 2
            elif conn_state == 'SYN_RECV':
                state_code = 3
            elif conn_state == 'FIN_WAIT':
                state_code = 4
            elif conn_state == 'TIME_WAIT':
                state_code = 5
            elif conn_state == 'CLOSE':
                state_code = 6
            elif conn_state == 'CLOSE_WAIT':
                state_code = 7
            elif conn_state == 'LAST_ACK':
                state_code = 8
            elif conn_state == 'LISTEN':
                state_code = 9
            elif conn_state == 'CLOSING':
                state_code = 10
            
            # 连接频率（每分钟）
            conn_frequency = connection_data.get('frequency', 1)
            
            # 加密流量标记
            is_encrypted = 1 if connection_data.get('is_encrypted', False) else 0
            
            # 数据块大小（平均包大小）
            packet_size = connection_data.get('packet_size', 0) / 1024  # KB
            
            # 连接是否来自或去往常见的云服务提供商
            is_cloud_provider = 1 if connection_data.get('is_cloud_provider', False) else 0
            
            # 组合特征向量
            feature_vector = [
                conn_type,
                is_known_port,
                remote_port_norm,
                data_sent,
                data_recv,
                duration,
                state_code,
                conn_frequency,
                is_encrypted,
                packet_size,
                is_cloud_provider
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def analyze_connection(self, connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析网络连接并检测异常"""
        # 添加到观察集合
        self.parent.add_observation('network', connection_data)
        
        # 如果没有模型，则返回空结果
        if self.parent.models['network'] is None:
            return {}
        
        # 提取特征并检测异常
        features = self.extract_features([connection_data])
        
        if features.size == 0:
            return {}
        
        # 应用特征缩放
        scaled_features = self.parent.scalers['network'].transform(features)
        
        # 预测并获取异常分数
        score = float(self.parent.models['network'].decision_function(scaled_features)[0])
        prediction = self.parent.models['network'].predict(scaled_features)[0]
        
        # 如果是异常，返回异常信息
        if prediction == -1:
            return {
                'remote_ip': connection_data.get('remote_ip', ''),
                'remote_port': connection_data.get('remote_port', 0),
                'protocol': connection_data.get('protocol', ''),
                'anomaly_score': score,
                'severity': self.parent._calculate_severity(score),
                'detection_time': datetime.now().isoformat(),
                'details': self._generate_anomaly_details(connection_data, score)
            }
        
        return {}
    
    def _generate_anomaly_details(self, connection_data: Dict[str, Any], score: float) -> Dict[str, Any]:
        """生成网络连接异常的详细信息"""
        details = {
            'unusual_aspects': [],
            'risk_factors': [],
            'recommendation': ""
        }
        
        remote_ip = connection_data.get('remote_ip', '')
        remote_port = connection_data.get('remote_port', 0)
        protocol = connection_data.get('protocol', '')
        local_port = connection_data.get('local_port', 0)
        
        # 检查不常见端口的连接
        if remote_port not in self.known_ports and remote_port > 1024:
            details['unusual_aspects'].append(f"连接到不常见端口: {remote_port}")
            details['risk_factors'].append("非标准端口连接可能表明隐蔽通道或规避检测")
        
        # 检查大量数据传输
        data_sent = connection_data.get('data_sent', 0)
        data_recv = connection_data.get('data_recv', 0)
        if data_sent > 10 * 1024 * 1024:  # 10MB
            details['unusual_aspects'].append(f"大量数据发送: {data_sent/(1024*1024):.2f} MB")
            details['risk_factors'].append("大量出站流量可能表明数据外泄")
        if data_recv > 10 * 1024 * 1024:  # 10MB
            details['unusual_aspects'].append(f"大量数据接收: {data_recv/(1024*1024):.2f} MB")
            details['risk_factors'].append("大量入站流量可能表明下载恶意软件")
        
        # 检查非工作时间的网络活动
        timestamp = connection_data.get('timestamp', time.time())
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        if hour >= 22 or hour <= 5:
            details['unusual_aspects'].append(f"非工作时间的网络活动 ({dt.strftime('%H:%M')})")
            details['risk_factors'].append("非标准时间的连接可能表明未授权活动")
        
        # 检查频繁的连接尝试
        frequency = connection_data.get('frequency', 1)
        if frequency > 10:
            details['unusual_aspects'].append(f"频繁的连接尝试 ({frequency}次/分钟)")
            details['risk_factors'].append("频繁连接尝试可能表明端口扫描或暴力破解")
        
        # 检查不常见的协议
        if protocol not in ['tcp', 'udp']:
            details['unusual_aspects'].append(f"使用不常见的协议: {protocol}")
            details['risk_factors'].append("非标准协议可能表明隐蔽通道")
        
        # 检查可疑的连接模式
        is_beacon = connection_data.get('is_beacon', False)
        if is_beacon:
            details['unusual_aspects'].append("检测到信标连接模式")
            details['risk_factors'].append("周期性连接可能表明命令与控制通信")
        
        # 检查异常的连接持续时间
        duration = connection_data.get('duration', 0)
        if duration > 24 * 3600:  # 24小时
            details['unusual_aspects'].append(f"长时间连接: {duration/3600:.2f}小时")
            details['risk_factors'].append("长期连接可能表明持久化后门或监控")
        
        # 检查是否连接到已知的恶意IP
        is_known_bad = connection_data.get('is_known_bad', False)
        if is_known_bad:
            details['unusual_aspects'].append(f"连接到已知恶意IP: {remote_ip}")
            details['risk_factors'].append("与已知恶意主机通信表明可能的感染")
        
        # 基于发现的异常提供建议
        if len(details['unusual_aspects']) > 0:
            details['recommendation'] = f"建议调查与{remote_ip}:{remote_port}的连接，检查涉及的进程和数据。"
            
            if is_known_bad:
                details['recommendation'] += f" 立即隔离发起该连接的主机并进行深入取证。"
            elif data_sent > 10 * 1024 * 1024:
                details['recommendation'] += f" 检查传输的数据内容，确认是否存在数据泄露。"
                
            if abs(score) > 0.8:
                details['recommendation'] += " 此连接显示为高风险，建议优先调查。"
        
        return details

# 行为分析模块的工具函数
def build_baseline_from_current_system(analyzer: BehaviorAnalyzer, duration_minutes: int = 60) -> None:
    """
    从当前系统状态构建行为基线
    
    Args:
        analyzer: 行为分析器实例
        duration_minutes: 收集基线数据的时间（分钟）
    """
    logger.info(f"开始收集系统基线数据，持续{duration_minutes}分钟...")
    
    start_time = time.time()
    end_time = start_time + (duration_minutes * 60)
    
    # 数据集合
    process_data = []
    user_data = []
    system_data = []
    file_data = []
    network_data = []
    
    # 每5秒采样一次
    while time.time() < end_time:
        # 收集进程数据
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_data = analyzer.process_analyzer._get_full_process_info(proc)
                if proc_data:
                    process_data.append(proc_data)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # 收集系统资源数据
        sys_data = analyzer.system_analyzer.get_system_data()
        if sys_data:
            system_data.append(sys_data)
        
        # 暂停5秒
        time.sleep(5)
    
    logger.info(f"基线数据收集完成。进程样本: {len(process_data)}，系统资源样本: {len(system_data)}")
    
    # 构建基线
    if process_data:
        analyzer.establish_baseline('process', process_data)
    if system_data:
        analyzer.establish_baseline('system', system_data)
    
    # 文件和网络基线可能需要更复杂的收集方法，这里暂时忽略
    logger.info("系统基线构建完成")


def detect_system_anomalies(analyzer: BehaviorAnalyzer) -> Dict[str, Any]:
    """
    检测系统中的异常行为
    
    Args:
        analyzer: 行为分析器实例
        
    Returns:
        包含检测到的所有异常的报告
    """
    anomalies = {}
    
    # 分析进程
    process_anomalies = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_data = analyzer.process_analyzer._get_full_process_info(proc)
            if proc_data:
                result = analyzer.process_analyzer.analyze_process(proc_data)
                if result:
                    process_anomalies.append(result)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    if process_anomalies:
        anomalies['process'] = process_anomalies
    
    # 分析系统资源
    system_result = analyzer.system_analyzer.analyze_system_resources()
    if system_result:
        anomalies['system'] = [system_result]
    
    # 生成报告
    return analyzer.generate_report(anomalies)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # 创建行为分析器实例
    analyzer = BehaviorAnalyzer()
    
    # 从当前系统状态构建基线
    build_baseline_from_current_system(analyzer, duration_minutes=10)
    
    # 检测系统异常
    report = detect_system_anomalies(analyzer)
    
    # 输出报告
    print(json.dumps(report, indent=2))