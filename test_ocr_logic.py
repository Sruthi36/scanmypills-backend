import re
import unittest

def extract_expiry(text):
    patterns = [
        r'(?:EXP|EXPIRY|ED|E\s*X\s*P|BEST|VALID)[\.\s:;-]*([A-Z0-9]{3,9})[\.\s/-]*([0-9OISLBS]{2,4})',
        r'(?:EXP|EXPIRY|ED|E\s*X\s*P|BEST|VALID)[\.\s:;-]*([0-9OISLBS]{1,2})[\.\s/-]+([0-9OISLBS]{2,4})',
        r'\b([0-9OISLBS]{1,2})[\.\s/-]+([0-9OISLBS]{2,4})\b',
        r'\b([A-Z0-9]{3,9})[\.\s/-]+([0-9OISLBS]{2,4})\b',
    ]
    month_map = {
        "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
        "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
        "SEPT": 9, "JANUARY": 1, "FEBRUARY": 2, "MARCH": 3, "APRIL": 4,
        "JUNE": 6, "JULY": 7, "AUGUST": 8, "OCTOBER": 10, "NOVEMBER": 11, "DECEMBER": 12
    }
    text = text.upper()
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            try:
                g1 = match.group(1).strip()
                g2 = match.group(2).strip()
                def normalize_num(s):
                    return s.replace('O', '0').replace('I', '1').replace('L', '1').replace('|', '1').replace('S', '5').replace('B', '8')
                month = 0
                if any(c.isalpha() for c in g1):
                    clean_month = re.sub(r'[^A-Z]', '', g1)
                    month = month_map.get(clean_month[:3], 0)
                    if month == 0:
                        if 'JU1' in clean_month: month = 7
                        elif 'MA1' in clean_month: month = 5
                else:
                    month_str = normalize_num(g1)
                    month = int(month_str)
                if not (1 <= month <= 12): continue
                year_str = normalize_num(g2)
                year = int(year_str)
                if year < 100: year += 2000
                if 2015 < year < 2050:
                    return f"{year}-{month:02d}-01"
            except: continue
    return None

def extract_manufacturer(text):
    text = text.upper()
    text = text.replace('R®', ' ').replace('®', ' ').replace('™', ' ')
    boundary_keywords = r'LTD|PVT|LIMITED|CORP|INC|PHARMA|PHAR|HEALTHCARE|INDUSTRIES|LABS|LABORATORIES|ORGANICS'
    mfd_pattern = r'(?:MKTD|MARKETED|MFD|MFG|MANUFACTURED|DISTRIBUTED)[\.\s]*BY[\.\s:;]*([\w\s\-\.\,\']{3,50})(?:\s(?:' + boundary_keywords + r'))?'
    match = re.search(mfd_pattern, text, re.I)
    if match:
        name = match.group(1).strip().split('\n')[0].strip()
        if ',' in name: name = name.split(',')[0].strip()
        words = name.split()
        if len(words) > 4: name = " ".join(words[:4])
        name = re.sub(r'[\s]R$', '', name)
        name = name.rstrip('., ')
        for bk in ['LTD', 'PVT LTD', 'LIMITED', 'INC', 'CORP', 'PHARMACEUTICALS', 'INDUSTRIES', 'LABS', 'LABORATORIES', 'ORGANICS']:
            if bk in text[match.start():match.start()+150]:
                if bk not in name: name += " " + bk
                break
        if len(name) > 3: return name.title()
    return "Unknown Manufacturer"

def extract_name(text):
    lines = text.split('\n')
    scored_names = []
    for line in lines:
        line = line.strip()
        if len(line) < 3: continue
        upper_line = line.upper()
        
        # Aggressive noise filtering synced with app.py
        noise_words = ['EXP', 'EXPIRY', 'MFG', 'MFD', 'BATCH', 'LOT', 'MRP', 'PRICE', 'LTD', 'LIMITED', 'PVT', 'PHARMACEUTICALS', 'MANUFACTURED', 'MARKETED', 'COMPOSITION', 'CONTAINS', 'EACH', 'DOSAGE', 'WARNING', 'SCHEDULE', 'STORAGE', 'STORE']
        if any(kw in upper_line for kw in noise_words): continue
        
        if not any(c.isalpha() for c in line): continue
        upper_chars = sum(1 for c in line if c.isupper())
        if line[0].isalpha() and upper_chars >= 1:
            score = len(line)
            if len(line) > 25: score -= 20
            if any(c.isdigit() for c in line): score += 10
            if '-' in line: score += 5
            if upper_chars / len(line) > 0.4: score += 10
            if any(kw in upper_line for kw in ['TABLET', 'CAPSULE', 'SYRUP', 'INJECTION']): score -= 5
            scored_names.append((score, line))
    if scored_names:
        scored_names.sort(key=lambda x: x[0], reverse=True)
        return scored_names[0][1]
    return "Unknown Medicine"

class TestOCR(unittest.TestCase):
    def test_expiry_extraction(self):
        self.assertEqual(extract_expiry("EXP. 12/2026"), "2026-12-01")
        self.assertEqual(extract_expiry("EXPIRY DATE: JUN 2025"), "2025-06-01")
        self.assertEqual(extract_expiry("EXP. 12/2O26"), "2026-12-01") 
        self.assertEqual(extract_expiry("EXP: JUL/27"), "2027-07-01") 
        
    def test_manufacturer_extraction(self):
        self.assertEqual(extract_manufacturer("MFG BY MANKIND PHARMA LTD"), "Mankind Pharma Ltd")
        self.assertEqual(extract_manufacturer("Mfd By: Cipla Limited, Mumbai"), "Cipla Limited")

    def test_user_examples(self):
        # Example 1: S-Numlo
        text1 = """
        S (-) Amlodipine Besylate IP
        S-Numlo-5
        Expiry MAR.2021
        Manufactured by Emcure PHARMACEUTICALS LTD.
        """
        self.assertEqual(extract_expiry(text1), "2021-03-01")
        self.assertEqual(extract_manufacturer(text1), "Emcure Pharmaceuticals Ltd")
        self.assertEqual(extract_name(text1), "S-Numlo-5")

        # Example 2: Cetirizine / Okacet
        text2 = """
        Cetirizine Hydrochloride Tablets IP 10 mg
        Okacet
        EXP.DEC.24
        Mfd. by CIPLA LTD.
        """
        self.assertEqual(extract_expiry(text2), "2024-12-01")
        self.assertEqual(extract_manufacturer(text2), "Cipla Ltd")
        res_name = extract_name(text2)
        self.assertTrue("CETIRIZINE" in res_name.upper() or "OKACET" in res_name.upper(), f"Unexpected name: {res_name}")

if __name__ == '__main__':
    unittest.main()
