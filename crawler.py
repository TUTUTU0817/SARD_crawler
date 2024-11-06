from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException
import time
import csv
import json
import hashlib
import re
import os
import logging

# 設定 logging 基本配置
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("output.log", mode="a"),
                              logging.StreamHandler()])

# 設定 webdriver
options = Options()
options.headless = True 
driver = webdriver.Chrome(options=options)
base_url = "https://samate.nist.gov/SARD/test-cases/search?language%5B%5D=java&flaw%5B%5D="

# cwe列表 
cwe_list = ["CWE-22","CWE-23","CWE-35","CWE-59","CWE-200","CWE-201","CWE-219","CWE-264","CWE-275","CWE-276","CWE-284","CWE-285","CWE-352",
            "CWE-359","CWE-377","CWE-402","CWE-425","CWE-441","CWE-497","CWE-538","CWE-540","CWE-548","CWE-552","CWE-566","CWE-601","CWE-639",
            "CWE-651","CWE-668","CWE-706","CWE-862","CWE-863","CWE-913","CWE-922","CWE-1275"]
# cwe_list = ["CWE-35", "CWE-59"]


# 初始化driver
def initialize_driver():
    """Initialize the WebDriver with options."""
    driver = webdriver.Chrome(options=options)
    return driver

# 計算程式碼hash值
def get_code_hash(code_dict):
    code_str = json.dumps(code_dict)
    # 使用 SHA-256 哈希
    return hashlib.sha256(code_str.encode()).hexdigest()

# 讀取或初始化進度檔案，回傳進度數據
def load_progress(progress_file):
    if os.path.exists(progress_file):
        try:
            with open(progress_file, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in progress file. Reinitializing progress data.")
    return {"completed_CWE" : [], "completed_links": {}}

# 保存當前進度到檔案
def save_progress(progress_data, progress_file):
    with open(progress_file, "w") as f:
        json.dump(progress_data, f, indent=4)            

# 更新進度檔案：標記 CWE 或 link 已完成
def update_progress(progress_data, progress_file, cwe_id, link=None):
    if link:
        # 初始化 completed_links[cwe_id] 清單
        if cwe_id not in progress_data["completed_links"]:
            progress_data["completed_links"][cwe_id] = []
        # 追加新的 link，避免重複
        if link not in progress_data["completed_links"][cwe_id]:
            progress_data["completed_links"][cwe_id].append(link)
    else:
        progress_data["completed_CWE"].append(cwe_id)
    save_progress(progress_data, progress_file)

# 蒐集所有有關此cwe之網頁連結
def collect_all_links(driver, cwe_id):
    """Navigate to a specific CWE page and return all case links."""
    driver.get(base_url + cwe_id)
    all_links = [] # 儲存所有抓取到的連結
    
    # 抓取結果中的每個連結
    while True:
        try:
            links = [element.get_attribute("href") for element in WebDriverWait(driver, 10).until(
                EC.presence_of_all_elements_located((By.CSS_SELECTOR, "li.card.test-case-card.animated a"))
            )]
            all_links.extend(links)

            # 檢查是否有“下一頁”按鈕
            try:
                next_button = WebDriverWait(driver, 10).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "span.next a"))
                )
                next_button.click()
                WebDriverWait(driver, 10).until(EC.staleness_of(next_button))
            except Exception:
                logging.info("No more pages. => start collect")
                break
        except Exception as e:
            logging.info(f"Skipping {cwe_id} due to no links found.")
            break
    return all_links

# 處理漏洞行可能有多行或單行情形
def parse_line_range(line_range_text):
    """Parse line range text (e.g., 'line 22', 'lines 22 to 50') and return start and end line numbers."""
    # 檢查是否為單行格式(e.g., "line 220")
    match_single = re.match(r"line (\d+)", line_range_text, re.IGNORECASE)
    if match_single:
        start_line = int(match_single.group(1))
        return start_line, start_line
    
    # 檢查是否為多行(e.g., "line 220 to 500")
    match_range = re.match(r"lines (\d+)\s+to+\s+(\d+)", line_range_text, re.IGNORECASE)
    if match_range:
        start_line = int(match_range.group(1))
        end_line = int(match_range.group(2))
        return start_line, end_line
    # 若有其他格式則拋出錯誤
    raise ValueError(f"Invalid line range format: {line_range_text}")

# 找漏洞行
def find_buggy_lines(driver, file_name, line_info, max_retries=3):
    """Find and return buggy lines."""
    buggy_lines = []
    try:
        # 解析行數範圍
        start_line, end_line = parse_line_range(line_info)
        # 點擊漏洞檔案
        buggy_file_button = WebDriverWait(driver, 20).until(
            EC.element_to_be_clickable((By.XPATH, f"//li[@class='tree-item location-item']//span[text()='{file_name}']/following-sibling::span[text()='{line_info.split(' ')[1]}']"))
        )
        # time.sleep(2)
        # driver.execute_script("arguments[0].scrollIntoView(true);", buggy_file_button)  # 確保元素可見
        # time.sleep(2)
        buggy_file_button.click()
        time.sleep(0.5)
        buggy_file_button.click()
        time.sleep(2)
        logging.info(f"==> Collected buggy line for {file_name} - {line_info}")
        
        # 找到指定漏洞行
        for line_number in range(start_line, end_line + 1):
            for attempt in range(max_retries):
                try:
                    # 有問題的行
                    buggy_region = WebDriverWait(driver, 20).until(
                        EC.presence_of_all_elements_located((By.XPATH, f"//div[@class='CodeMirror-linenumber CodeMirror-gutter-elt'][text()='{line_number}']/ancestor::div[@class='CodeMirror-gutter-wrapper bad buggy-region']/following-sibling::pre[@class=' CodeMirror-line buggy-region bad']"))
                    )
                    driver.execute_script("arguments[0].scrollIntoView(true);", buggy_region[0])  # 確保元素可見
                    
                    for line in buggy_region:
                        buggy_lines.append(line.text.strip())
                    
                            
                except TimeoutException:
                    logging.warning(f"Line {line_number} not found or failed to load.")
                    if attempt < max_retries - 1:
                        buggy_file_button.click()
                        time.sleep(2)  # 等待幾秒後重新嘗試
                    else:
                        return None
        # logging.info(f"{file_name} buggy collect success!")
    except Exception as e:
        logging.error(f"Error finding buggy lines for {file_name}: {e}")
        return None
    return buggy_lines

# 再蒐集程式碼時做行數跟程式碼內容的處理
def process_line_text(line_element):
    """Processes the text of a line element, returning line number and code."""
    line_content = line_element.text.split("\n")
    line_number = line_content[0] if line_content[0].isdigit() else None
    code_text = line_content[1] if len(line_content) > 1 else ""
    return line_number, code_text

# 滾動並且蒐集所有程式碼
def collect_code_lines(driver, file_name):
    code_lines = {}
    code_lines_len = 0
    logging.info(f"=> Collected code for {file_name}")
    # 點擊漏洞檔案
    buggy_file_button = WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.XPATH, f"//li[@class='tree-item location-item']//span[text()='{file_name}']"))
    )
    driver.execute_script("arguments[0].scrollIntoView(true);", buggy_file_button)  # 確保元素可見
    buggy_file_button.click()        
    
    time.sleep(1)  # 調整等待時間以符合加載速度

    
    
    # 找到程式碼容器
    code_container = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CLASS_NAME, "CodeMirror-code"))
    ) 

    # 找到垂直滾動條元素
    v_scrollbar = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CLASS_NAME, "CodeMirror-vscrollbar"))
    )

    # 滾動到最上方
    driver.execute_script("arguments[0].scrollTop = 0;", v_scrollbar)
    time.sleep(2)  # 調整等待時間以符合加載速度
    
    # 初次抓取顯示的行
    visible_lines = code_container.find_elements(By.XPATH, ".//div[@style='position: relative;']")

    for line in visible_lines:
        line_number, code_text = process_line_text(line)
        if line_number:
            code_lines[line_number] = code_text
            
    # 持續滾動並抓取程式碼
    while True:
        try:
            # 滾動頁面，顯示下一批行
            driver.execute_script("arguments[0].scrollIntoView(true);",visible_lines[-1])  
            time.sleep(2)  # 調整等待時間以符合加載速度

            # 抓取目前可見的行
            new_visible_lines = code_container.find_elements(By.XPATH, ".//div[@style='position: relative;']")
            
            for line in new_visible_lines:
                line_number, code_text = process_line_text(line)
                if line_number:
                    code_lines[line_number] = code_text
            
            # 更新目前顯示的行
            visible_lines = new_visible_lines
            
            # 檢查是否還有新行加載，否則結束
            if len(code_lines) != code_lines_len:
                code_lines_len = len(code_lines)
            else:
                break
            final_code = dict(sorted(code_lines.items(), key=lambda item: int(item[0])))
            
            
        except StaleElementReferenceException:
            # 捕捉重新加載的行為並重新獲取元素
            code_container = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "CodeMirror-code"))
            ) 
            # 找到垂直滾動條元素
            v_scrollbar = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "CodeMirror-vscrollbar"))
            )
        except Exception as e:
            logging.warning("unexcept error :", e)
            return None         
    return final_code


# 蒐集所有程式碼資訊(檔名、漏洞行、程式碼)
def collect_code_data(driver, cwe_id, link):
    """Collect code data from each test case link."""
    driver.get(link)
    json_data = {}
    
    try:

        # 使用 JavaScript 設置 div 的寬度為 100%
        driver.execute_script("document.querySelector('#left-pane').style.width = '100%';")

        file_elements = WebDriverWait(driver, 20).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, "li.tree-item.location-item span"))
        )
        file_info = [file_elements[i:i+3] for i in range(0, len(file_elements), 3)]
        
        # 還原原始寬度
        # driver.execute_script(f"document.querySelector('#left-pane').style.width = 'calc(26.1039% - 2.5px)';")

        title_div = driver.find_element(By.CLASS_NAME, "title")
        title = title_div.find_element(By.TAG_NAME, "h1").text
                
        for group in file_info:
            try:
                ##### TODO: 1. 抓取不到line info，應該使用更精準的定位法
                file_name, line_info, cwe_type = group[0].text, group[1].text, group[2].text
                if cwe_type == cwe_id:
                    logging.info(f"Collected data for {title} - {file_name} -----------------------------------------------")
                    
                    # 漏洞行蒐集                
                    buggy_lines = find_buggy_lines(driver, file_name, line_info)
                   
                    if buggy_lines is None:
                        return None  # 若發生問題回傳None，避免記錄此link
                    
                    # 程式碼蒐集
                    final_code = collect_code_lines(driver, file_name)
                    
                    if final_code is None:
                        return None  # 若發生問題回傳None，避免記錄此link
                    

                    # 計算當前程式碼內容的哈希值
                    code_hash = get_code_hash(final_code)
                                                        
                    # 檢查是否已經蒐集過相同的程式碼內容
                    unique_key = f"{cwe_id}_{code_hash}"
                    
                    
                    # 檢查並合併到 json_data 中
                    if unique_key in json_data:
                        logging.info(f"=> Skipping duplicate code for {file_name}")
                        if line_info not in json_data[unique_key]["line"]:
                            json_data[unique_key]["line"].append(line_info)
                            json_data[unique_key]["buggy_line"].extend(buggy_lines)  # 新增到現有 buggy_line 清單
                    else:
                        json_data[unique_key] = {
                            "cwe_id": cwe_id,
                            "title": title,
                            "file_name": file_name,
                            "line": [line_info],
                            "code": final_code,  # 可根據需求填充完整程式碼
                            "buggy_line": buggy_lines,  # 直接儲存為清單
                            "label": 1
                        }
            except Exception as e:
                logging.error(f"Error collecting data for file {file_name}: {e}")
                return None # 若發生問題回傳None，避免記錄此link
    except Exception as e:
        logging.error("link Error:", e)
        return None # 若發生問題回傳None，避免記錄此link
        
    return json_data


# 儲存到CSV和JSON檔案
def save_to_csv_and_json(cwe_id, code_data, csv_file_path, json_file_path):
    # 讀取現有的 JSON 資料
    try:
        with open(json_file_path, "r") as json_file:
            json_data = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.info("Initializing empty result JSON file...")
        json_data = []  # 若無檔案或格式錯誤，初始化為空列表
    
    # 打開 CSV 並準備寫入
    with open(csv_file_path, mode="a", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        # 若文件為空則寫入標題行
        if csv_file.tell() == 0:
            csv_writer.writerow(["cwe_id", "title", "file_name", "line_info", "code", "buggy_line", "label"])

        # 更新 CSV 和 JSON 資料
        for file_name, data in code_data.items():
            csv_writer.writerow([cwe_id, data["title"], file_name, data["line"], data["code"], data["buggy_line"], data["label"]])
            json_data.append(data)

    # 將更新後的 JSON 資料寫回文件
    with open(json_file_path, "w") as json_file:
        json.dump(json_data, json_file, indent=4)

# 主程式開始
def main():
    # 設定進度檔案路徑
    progress_file = "progress.json"
    json_file_path = "collected_code_all.json"
    csv_file_path = "collected_code_all.csv"

    # 初始化進度資料
    progress_data = load_progress(progress_file)
    # 初始化 driver
    driver = initialize_driver()
    try:
        for cwe_id in cwe_list:
            if cwe_id in progress_data["completed_CWE"]:
                logging.info(f"Skipping completed {cwe_id}")
                continue
            
            all_links = collect_all_links(driver, cwe_id)
            
            for link in all_links:
                if cwe_id in progress_data["completed_links"] and link in progress_data["completed_links"][cwe_id]:
                    logging.info(f"Skipping completed link for {cwe_id}")
                    continue
                try:
                    # code 資料蒐集與儲存
                    code_data = collect_code_data(driver, cwe_id, link)
                    
                    # 若有問題，跳過避免更新紀錄
                    if code_data is None:
                        logging.warning(f"Skipping progress update for link {link} due to errors.")
                        continue
                    
                    # 儲存到CSV和JSON
                    save_to_csv_and_json(cwe_id, code_data, csv_file_path, json_file_path)
                    # 更新進度並且保存進度檔案
                    update_progress(progress_data, progress_file, cwe_id, link)
                except Exception as e:
                    logging.warning(f"Error processing link {link} for {cwe_id}: {e}")
                    continue
            
            # 檢查該 CWE 是否所有連結都已完成
            completed_links_for_cwe = progress_data["completed_links"].get(cwe_id, [])
            if len(completed_links_for_cwe) == len(all_links):
                # 當完成整個 CWE 的所有 link 後，標記 CWE 為已完成  
                update_progress(progress_data, progress_file, cwe_id)
                logging.info(f"Completed CWE-{cwe_id}")
    finally:
        # 關閉瀏覽器
        driver.quit()
                


if __name__ == "__main__":
    main()


            