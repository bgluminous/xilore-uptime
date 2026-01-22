// ============ 初始化页面专用的 setup 对象 ============
const setupApp = {
  currentStep: 1,
  dbConfig: null,
  dbHasAdmin: false,
  
  init() {
    this.bindEvents();
  },
  
  bindEvents() {
    document.getElementById('db-form').addEventListener('submit', (e) => {
      e.preventDefault();
      // 如果数据库已有管理员，直接完成安装
      if (this.dbHasAdmin) {
        this.completeSetupWithExistingAdmin();
      } else {
        this.nextStep();
      }
    });
    
    document.getElementById('admin-form').addEventListener('submit', (e) => {
      e.preventDefault();
      this.completeSetup();
    });
  },
  
  async testDatabase() {
    const config = {
      host: document.getElementById('db-host').value,
      port: parseInt(document.getElementById('db-port').value),
      user: document.getElementById('db-user').value,
      password: document.getElementById('db-password').value,
      name: document.getElementById('db-name').value
    };
    
    const resultEl = document.getElementById('db-test-result');
    const nextBtn = document.getElementById('btn-step1-next');
    
    resultEl.className = 'test-result';
    resultEl.textContent = '正在测试连接...';
    resultEl.style.display = 'block';
    resultEl.style.background = '#f0f9ff';
    resultEl.style.color = 'var(--accent)';
    resultEl.style.border = '1px solid #bae6fd';
    
    try {
      const response = await fetch('/api/install/test-db', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      
      const result = await response.json();
      
      if (result.success) {
        this.dbConfig = config;
        this.dbHasAdmin = result.hasAdmin;
        
        if (result.hasAdmin) {
          // 数据库已有管理员，可以直接使用
          resultEl.className = 'test-result success';
          resultEl.innerHTML = `✓ ${result.message}<br><small style="opacity:0.8">点击"完成"直接使用现有数据</small>`;
          nextBtn.textContent = '完成';
          nextBtn.disabled = false;
        } else if (result.initialized) {
          // 数据库已初始化但没有管理员
          resultEl.className = 'test-result success';
          resultEl.innerHTML = `✓ 数据库已初始化，但没有管理员账户<br><small style="opacity:0.8">请创建管理员账户</small>`;
          nextBtn.textContent = '下一步';
          nextBtn.disabled = false;
        } else {
          // 全新数据库
          resultEl.className = 'test-result success';
          resultEl.textContent = '✓ ' + result.message;
          nextBtn.textContent = '下一步';
          nextBtn.disabled = false;
        }
      } else {
        resultEl.className = 'test-result error';
        resultEl.textContent = '✗ ' + result.message;
        nextBtn.disabled = true;
        this.dbHasAdmin = false;
      }
    } catch (e) {
      resultEl.className = 'test-result error';
      resultEl.textContent = '✗ 连接失败: ' + e.message;
      document.getElementById('btn-step1-next').disabled = true;
      this.dbHasAdmin = false;
    }
  },
  
  nextStep() {
    if (this.currentStep >= 3) return;
    
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.remove('active');
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.add('completed');
    this.currentStep++;
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.add('active');
    
    document.querySelectorAll('.setup-step-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`step-${this.currentStep}`).classList.add('active');
  },
  
  goToStep(step) {
    // 更新步骤指示器
    for (let i = 1; i <= 3; i++) {
      const stepEl = document.querySelector(`.step[data-step="${i}"]`);
      stepEl.classList.remove('active', 'completed');
      if (i < step) stepEl.classList.add('completed');
      if (i === step) stepEl.classList.add('active');
    }
    this.currentStep = step;
    
    document.querySelectorAll('.setup-step-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`step-${step}`).classList.add('active');
  },
  
  prevStep() {
    if (this.currentStep <= 1) return;
    
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.remove('active');
    this.currentStep--;
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.remove('completed');
    document.querySelector(`.step[data-step="${this.currentStep}"]`).classList.add('active');
    
    document.querySelectorAll('.setup-step-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`step-${this.currentStep}`).classList.add('active');
  },
  
  // 使用已有管理员完成安装
  async completeSetupWithExistingAdmin() {
    try {
      const response = await fetch('/api/install/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          database: this.dbConfig,
          skipAdmin: true
        })
      });
      
      const result = await response.json();
      
      if (result.success) {
        document.getElementById('setup-complete-msg').textContent = '已连接到现有数据库，可以使用原有账户登录';
        this.goToStep(3);
      } else {
        alert(result.error || '安装失败');
      }
    } catch (e) {
      alert('安装失败: ' + e.message);
    }
  },
  
  async completeSetup() {
    const password = document.getElementById('admin-password').value;
    const passwordConfirm = document.getElementById('admin-password-confirm').value;
    
    if (password !== passwordConfirm) {
      alert('两次输入的密码不一致');
      return;
    }
    
    const adminConfig = {
      username: document.getElementById('admin-username').value,
      email: document.getElementById('admin-email').value,
      password: password
    };
    
    try {
      const response = await fetch('/api/install/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          database: this.dbConfig,
          admin: adminConfig,
          skipAdmin: false
        })
      });
      
      const result = await response.json();
      
      if (result.success) {
        document.getElementById('setup-complete-msg').textContent = 'Xilore UptimeBot 已成功初始化';
        this.nextStep();
      } else {
        alert(result.error || '安装失败');
      }
    } catch (e) {
      alert('安装失败: ' + e.message);
    }
  }
};

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
  setupApp.init();
});
