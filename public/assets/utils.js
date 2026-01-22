// 共享工具函数

// 排序函数：英文字母在中文前面
function sortByName(a, b) {
  const nameA = (a || '').trim();
  const nameB = (b || '').trim();
  
  if (!nameA && !nameB) return 0;
  if (!nameA) return 1;
  if (!nameB) return -1;
  
  // 获取首字符
  const firstCharA = nameA.charAt(0);
  const firstCharB = nameB.charAt(0);
  
  // 判断首字符是否是英文字母（a-z, A-Z）
  const isEnglishA = /^[a-zA-Z]/.test(firstCharA);
  const isEnglishB = /^[a-zA-Z]/.test(firstCharB);
  
  // 如果一个是英文，一个是中文，英文排在前面
  if (isEnglishA && !isEnglishB) return -1;
  if (!isEnglishA && isEnglishB) return 1;
  
  // 如果都是英文或都是中文，使用 localeCompare 排序
  return nameA.localeCompare(nameB, 'zh-CN', { numeric: true });
}
