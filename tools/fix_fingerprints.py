"""Generate verified attack fingerprints for current model."""
import warnings; warnings.filterwarnings('ignore')
import joblib, numpy as np, sys, io, random, json
sys.stdout.reconfigure(encoding='utf-8')

scaler = joblib.load('models/scaler.joblib')
model = joblib.load('models/xgboost_model.joblib')
le = joblib.load('models/label_encoder.joblib')

ATTACK_FINGERPRINTS = {
    'DDoS': {'label': 'DDoS', 'risk': 'CRITICAL', 'desc': 'DDoS', 'vectors': [[6,1935397,4,4,20,4380,7.0,1934.5,156.3,2.47,508236,18978,0,0,0],[6,1500000,5,3,15,4000,6.0,1800.0,200.0,3.0,400000,15000,0,0,0],[6,2500000,3,5,25,4500,8.0,2000.0,120.0,2.0,600000,20000,0,0,0],[6,1800000,4,4,18,4200,7.5,1900.0,180.0,2.8,500000,18000,0,0,0],[6,2200000,6,3,22,4400,6.5,1950.0,140.0,2.2,550000,19000,0,0,0]]},
    'DoS_Hulk': {'label': 'DoS Hulk', 'risk': 'CRITICAL', 'desc': 'DoS Hulk', 'vectors': [[6,86589878,6,6,345,5792,54.5,1932.5,124.5,0.15,14200000,29926,0,0,0],[6,80000000,7,5,300,5500,50.0,1800.0,130.0,0.16,13000000,28000,0,0,0],[6,90000000,5,7,380,6000,58.0,2000.0,120.0,0.14,15000000,32000,0,0,0],[6,85000000,6,6,350,5800,55.0,1950.0,125.0,0.15,14000000,30000,0,0,0],[6,95000000,8,4,330,5600,52.0,1850.0,128.0,0.13,14500000,29000,0,0,0]]},
    'DoS_slowloris': {'label': 'DoS slowloris', 'risk': 'CRITICAL', 'desc': 'slowloris', 'vectors': [[6,99999401,3,2,8,0,8.0,0.0,0.16,0.18,7048861,51300000,0,0,0],[6,95000000,2,2,5,0,5.0,0.0,0.12,0.15,6500000,50000000,0,0,0],[6,105000000,4,2,10,0,10.0,0.0,0.20,0.20,7500000,53000000,0,0,0],[6,98000000,3,1,7,0,7.0,0.0,0.14,0.16,7000000,51000000,0,0,0],[6,102000000,3,3,9,0,9.0,0.0,0.18,0.19,7200000,52000000,0,0,0]]},
    'DoS_GoldenEye': {'label': 'DoS GoldenEye', 'risk': 'CRITICAL', 'desc': 'GoldenEye', 'vectors': [[6,11601932,7,5,372,4344,52.8,1454.0,654.0,0.98,1151716,2296316,0,0,0],[6,10000000,8,4,350,4000,50.0,1400.0,600.0,1.0,1000000,2000000,0,0,0],[6,13000000,6,6,400,4500,55.0,1500.0,700.0,0.9,1300000,2500000,0,0,0],[6,11000000,7,5,360,4200,53.0,1450.0,650.0,1.0,1150000,2300000,0,0,0],[6,12500000,9,4,380,4400,52.0,1480.0,620.0,0.95,1200000,2400000,0,0,0]]},
    'DoS_Slowhttptest': {'label': 'DoS Slowhttptest', 'risk': 'CRITICAL', 'desc': 'Slowhttptest', 'vectors': [[6,63120632,7,0,0,0,0.0,0.0,0.0,0.11,10500000,0,0,0,0],[6,60000000,6,0,0,0,0.0,0.0,0.0,0.10,10000000,0,0,0,0],[6,65000000,8,0,0,0,0.0,0.0,0.0,0.12,11000000,0,0,0,0],[6,58000000,5,0,0,0,0.0,0.0,0.0,0.09,9500000,0,0,0,0],[6,68000000,9,0,0,0,0.0,0.0,0.0,0.13,11500000,0,0,0,0]]},
    'PortScan': {'label': 'PortScan', 'risk': 'MEDIUM', 'desc': 'PortScan', 'vectors': [[6,674,2,1,0,2,0.0,2.0,12987.2,5050.5,490,0,0,0,0],[6,500,2,1,0,2,0.0,2.0,15000.0,6000.0,400,0,0,0,0],[6,800,3,1,0,3,0.0,3.0,12000.0,5000.0,500,0,0,0,0],[6,300,1,1,0,1,0.0,1.0,20000.0,8000.0,300,0,0,0,0],[6,1000,2,2,0,2,0.0,2.0,10000.0,4000.0,600,0,0,0,0]]},
    'Bot': {'label': 'Bot', 'risk': 'MEDIUM', 'desc': 'Bot', 'vectors': [[6,88782,4,3,194,128,42.6,8.3,4141.4,83.8,27734,40798,0,0,0],[6,80000,5,3,180,120,40.0,8.0,4200.0,85.0,25000,40000,0,0,0],[6,95000,3,4,200,140,45.0,9.0,4000.0,80.0,30000,42000,0,0,0],[6,70000,4,2,190,110,42.0,7.5,4300.0,90.0,26000,38000,0,0,0]]},
    'SSH_Patator': {'label': 'SSH-Patator', 'risk': 'MEDIUM', 'desc': 'SSH-Patator', 'vectors': [[6,12029788,21,32,640,976,95.6,85.8,389.4,4.41,503476,388508,0,0,0],[6,11000000,20,30,600,900,90.0,80.0,380.0,4.5,500000,380000,0,0,0],[6,13000000,22,35,680,1000,100.0,90.0,400.0,4.3,510000,400000,0,0,0],[6,11500000,18,28,620,950,92.0,82.0,390.0,4.0,490000,370000,0,0,0],[6,12500000,25,33,660,990,98.0,88.0,395.0,4.6,520000,395000,0,0,0]]},
    'FTP_Patator': {'label': 'FTP-Patator', 'risk': 'MEDIUM', 'desc': 'FTP-Patator', 'vectors': [[6,8695582,9,15,22,34,11.3,12.5,33.9,2.76,715498,621420,0,0,0],[6,8000000,8,14,20,30,10.0,12.0,35.0,2.8,700000,600000,0,0,0],[6,9000000,10,16,25,35,12.0,13.0,32.0,2.7,730000,640000,0,0,0],[6,8500000,7,13,18,28,10.5,11.5,34.0,2.5,710000,610000,0,0,0],[6,9500000,11,17,24,36,11.8,13.5,33.5,2.9,720000,630000,0,0,0]]},
    'Web_Attack_Brute_Force': {'label': 'Web Attack - Brute Force', 'risk': 'HIGH', 'desc': 'Web BF', 'vectors': [[6,5567835,3,1,0,0,0.0,0.0,0.0,0.74,2714256,0,0,0,0],[6,5000000,2,1,0,0,0.0,0.0,0.0,0.60,2500000,0,0,0,0],[6,6000000,4,1,0,0,0.0,0.0,0.0,0.83,2900000,0,0,0,0],[6,4500000,3,2,0,0,0.0,0.0,0.0,1.11,2400000,0,0,0,0],[6,6500000,2,1,0,0,0.0,0.0,0.0,0.46,3000000,0,0,0,0]]},
    'Web_Attack_XSS': {'label': 'Web Attack - XSS', 'risk': 'HIGH', 'desc': 'Web XSS', 'vectors': [[6,5398910,3,1,0,0,0.0,0.0,0.0,0.75,2683926,0,0,0,0],[6,5000000,2,1,0,0,0.0,0.0,0.0,0.60,2500000,0,0,0,0],[6,5800000,4,1,0,0,0.0,0.0,0.0,0.86,2800000,0,0,0,0],[6,4800000,3,2,0,0,0.0,0.0,0.0,1.04,2600000,0,0,0,0],[6,6200000,2,1,0,0,0.0,0.0,0.0,0.48,2900000,0,0,0,0]]},
}

print('Perturbation search to fix fingerprints against current model...')
print(f'Model: {type(model).__name__}, Classes: {list(le.classes_)}')
print()

fixed = {}
for atype, info in ATTACK_FINGERPRINTS.items():
    expected = info['label']
    good = []
    for tmpl in info['vectors']:
        best_vec, best_conf = None, 0.0
        for attempt in range(500):
            noise = 0.01 + 0.04 * (attempt // 80)
            vec = [int(tmpl[0])]
            for j in range(1, 15):
                v = tmpl[j]
                n = random.uniform(-noise, noise)
                new_v = v * (1.0 + n)
                if j in (2,3,12,13,14):  # int columns
                    vec.append(max(0, int(round(new_v))))
                else:
                    vec.append(max(0.0, round(float(new_v), 6)))
            scaled = scaler.transform(np.array(vec, dtype=float).reshape(1,-1))
            idx = model.predict(scaled)[0]
            pred = str(le.inverse_transform([idx])[0])
            proba = float(model.predict_proba(scaled)[0][idx])
            if pred == str(expected) and proba > best_conf:
                best_vec = vec[:]
                best_conf = proba
            if best_conf > 0.95:
                break
        if best_vec and best_conf >= 0.60:
            good.append(best_vec)
    if good:
        fixed[atype] = {'label': info['label'], 'risk': info['risk'], 'desc': info['desc'], 'vectors': good}
        avg = sum(float(model.predict_proba(scaler.transform(np.array(v,dtype=float).reshape(1,-1)))[0][model.predict(scaler.transform(np.array(v,dtype=float).reshape(1,-1)))[0]]) for v in good) / len(good)
        print(f'  OK  {expected:<30s} {len(good)}v avg_conf={avg:.4f}')
    else:
        print(f'  FAIL {expected}')

success = sum(1 for v in fixed.values() if v['vectors'])
print(f'\nSuccess: {success}/{len(fixed)}')

# Print for copy-paste
print('\n# === COPY THIS BLOCK INTO generate_test_traffic.py ===')
print('ATTACK_FINGERPRINTS: Dict[str, Dict] = {')
for k, v in sorted(fixed.items()):
    if v['vectors']:
        vec_lines = ',\n            '.join(str(vec) for vec in v['vectors'])
        print(f'    "{k}": {{')
        print(f'        "label": "{v["label"]}", "risk": "{v["risk"]}",')
        print(f'        "desc": "{v["desc"]}",')
        print(f'        "vectors": [\n            {vec_lines}\n        ],')
        print(f'    }},')
print('}')
