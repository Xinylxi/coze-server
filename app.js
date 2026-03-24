const express = require('express')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const crypto = require('crypto')

const app = express()
app.use(express.json())
app.use(require('cors')())  // 允许跨域请求

// === 配置区域 - 请替换为你的实际值 ===
const COZE_CONFIG = {
  appId: '1162063759694',  // OAuth应用ID
  publicKeyKid: '_7rZVoU75QFMPq5KCqqiz058BDV78y4KEcs7EKK4gcg',  // 公钥指纹
  privateKey: `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCsNyc4P8YFgg5j
8VH8aK1HQr8HoRik4TmZ8+tzWQSDmJmupaqYJIycp/JRngbbpeDnHb2sc4bu3vq0
SSgGwucF2ErjMLM7Vogo622FWSPUAVOpQ5cNWRvaCQ0HHSmQWKGIZesBGzjN41/i
ciXNzcPV+zb0NZz3JEPZB+ENBQpUKfoyHO09qN0F+69NwsKSrx574lI/NsfV6dt8
yZg9lK3T+sGETVQlS608gf61u8/wCRF38F4/aP0DXyb79pxek2X9ByltUcpDalqY
mafLo9hq+Tw0OCN8Rcd606UivTo2uD5ak9NrXhbnBiFuN6lFmI+xBSTMC3EHo+c4
dAFgp+zRAgMBAAECggEAKcavUuvVg5yLFR+DPfG+pxy/7n/b1JN2P6x2H2Mmvy2T
ilRRz9p96bqsA7SMAVh5+Fa0nlLgFq4srvNYLFu3YymW8QntUKWrHhIOXVzEXjd8
LgFhcTF+miO770/Zt1Roywe+PGR4ISnZJrt+BDC4Iv5v1En1K9a2Rr2skFX6rXOj
iKT3rZIBZEHo4ypfROojG6KpZqPEsB1pdJyf9eMXQ4KMlkiEwSTwJkDBYJ9KXVpU
au0wfhDu76OWf+fnfASJNOPB8Xew8ABh+Y4kaZFcUlCVpyxUaZkuiHtUpWpPbvGK
TgRkWnAKPc/2RRhzd0myQgUiSLNgsaMzW5RYtZcOYQKBgQDTJV48NMzixJKMCFje
HhNwcv5BwlapaK0Bx0uMoRh+uBS9sn6gz+dquK9BxX3EjmbW52m2F1fHESh2kz1U
513BVlyVReslruhW38fQRZgMKlLp9cKwvEACLVeTQA9WCTP+OtsKGCpovxbUrNGu
LTg4XbajOfF3tGNMrKNNJivjzQKBgQDQzKXz4ljKM3HhEmmQN8gnrYczJuaSHCzi
LbanL9bzxvGjtJyShZNjN2KrZYX5qHllaNr6zqyui7pXmFESlfcc6jewYNQy5ns4
N7TsCwaEmdgDuzjw7oBXjWoUxZ1bOHuhrlDSXIC8lhsZBEb1RS/53sP0OWnaU80y
MDplrkQxFQKBgQCeT9xSI/yi4mRGnlOTZtWIcI/22jGEH7noJXed34OwL3FNsjGD
fZ6zw/mTxPHBmEu/Qg9eui3UUicWkNthd4AyYABW4++ld3k4+dylaijQpkM4rE3n
mZ4cg8av304gYhIbwiFNdkUF+JCzsUgd4kXO7WTtCZrk99mkOaTPSZmK2QKBgCNI
4iaDsqOA7Bav6NzxQEbMQVO4mDBKyJ70QLCiGf4aOY2DoQ31usGCg48ZWfmlqdYk
URUfRfk9LaFN4S114EunnP+WbWWoo1wNtepJtrFD2khPJEE63L9u62VVO9FFi0b4
UTorXaoA59VjbqZWKdRc+9pStXuqu7tmgQfb2jQ9AoGBAIRdPLZ052Gwt9XUtOPw
iLx+RJXOHbv9mUjjjCVEI7XtqrtWirDQsaJuyQH6/gE0yD2N9tVZCoHdR3MXVBhm
ff1WfSrCg1cyWEYlGpSxnLIvHOXIlYOb1jDT5iVeizCdvD3ksQT3ThxARJeZ6OD2
r+s+l2rHMhpjIvmBQLEQDC/W
-----END PRIVATE KEY-----`
}
// ================================

/**
 * 生成随机字符串（用于jti防重放）
 */
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex')
}

/** 
 * 签署JWT
 */
function generateJWT(userId) {
  const now = Math.floor(Date.now() / 1000)
  
  const payload = {
    iss: COZE_CONFIG.appId,
    aud: 'api.coze.cn',
    iat: now,
    exp: now + 600,  // JWT有效期10分钟
    jti: generateRandomString(),
    session_name: userId || 'anonymous'  // 用于会话隔离
  }
  
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: COZE_CONFIG.publicKeyKid
  }
  
  return jwt.sign(payload, COZE_CONFIG.privateKey, {
    algorithm: 'RS256',
    header: header
  })
}

/**
 * 获取Access Token（缓存优化）
 */
let tokenCache = {
  accessToken: null,
  expiresAt: 0
}

async function getAccessToken(userId) {
  const now = Math.floor(Date.now() / 1000)
  
  // 如果缓存未过期，直接返回
  if (tokenCache.accessToken && tokenCache.expiresAt > now + 300) {
    return tokenCache.accessToken
  }
  
  // 生成新的JWT
  const jwtToken = generateJWT(userId)
  
  // 调用扣子API获取Access Token
  const response = await axios.post(
    'https://api.coze.cn/api/permission/oauth2/token',
    {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      duration_seconds: 3600  // Access Token有效期1小时
    },
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwtToken}`
      }
    }
  )
  
  // 缓存Access Token
  tokenCache = {
    accessToken: response.data.access_token,
    expiresAt: response.data.expires_in
  }
  
  return tokenCache.accessToken
}

/** 
 * 健康检查接口（微信云托管需要）
 */
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'coze-proxy' })
})

/**
 * 聊天接口
 */
app.post('/api/coze/chat', async (req, res) => {
  const { botId, message, userId } = req.body
  
  if (!botId || !message) {
    return res.status(400).json({
      success: false,
      error: '缺少必要参数: botId 和 message'
    })
  }
  
  try {
    // 1. 获取Access Token
    const accessToken = await getAccessToken(userId || 'default')
    
    // 2. 调用扣子聊天API
    const response = await axios.post(
      'https://api.coze.cn/v3/chat',
      {
        bot_id: botId,
        user_id: userId || 'anonymous',
        additional_messages: [{
          role: 'user',
          content: message,
          content_type: 'text'
        }],
        stream: false
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        }
      }
    )
    
    // 3. 返回结果
    res.json({
      success: true,
      reply: response.data.messages?.[0]?.content || '暂无回复',
      data: response.data
    })
    
  } catch (error) {
    console.error('API调用错误:', error.response?.data || error.message)
    
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.response?.data?.message || error.message
    })
  }
})

/** 
 * 流式聊天接口（可选）
 */
app.post('/api/coze/chat/stream', async (req, res) => {
  const { botId, message, userId } = req.body
  
  if (!botId || !message) {
    return res.status(400).json({
      success: false,
      error: '缺少必要参数'
    })
  }
  
  // 设置SSE响应头
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  
  try {
    const accessToken = await getAccessToken(userId || 'default')
    
    const response = await axios.post(
      'https://api.coze.cn/v3/chat',
      {
        bot_id: botId,
        user_id: userId || 'anonymous',
        additional_messages: [{
          role: 'user',
          content: message,
          content_type: 'text'
        }],
        stream: true
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        },
        responseType: 'stream'
      }
    )
    
    // 转发流式响应
    response.data.on('data', (chunk) => {
      res.write(chunk)
    })
    
    response.data.on('end', () => {
      res.end()
    })
    
    response.data.on('error', (err) => {
      console.error('流式传输错误:', err)
      res.end()
    })
    
  } catch (error) {
    console.error('流式聊天错误:', error.message)
    res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`)
    res.end()
  }
})

// 启动服务
const PORT = process.env.PORT || 8080
app.listen(PORT, () => {
  console.log(`服务启动成功，端口: ${PORT}`)
})