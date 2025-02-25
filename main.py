from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
import edge_tts
import asyncio
import io
import os
from pathlib import Path

# JWT 配置
# SECRET_KEY 用于签名 JWT 令牌，在生产环境中应通过环境变量设置
SECRET_KEY = os.environ.get("SECRET_KEY", "abcd1234")
# 使用 HS256 算法进行 JWT 签名
ALGORITHM = "HS256"
# 令牌有效期（分钟）
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 创建 FastAPI 应用实例
app = FastAPI(title="Text-to-Speech API")

# 配置跨域资源共享 (CORS)
# 允许来自 Chrome 扩展的请求访问此 API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该限制为你的扩展 ID
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 数据模型定义
# 用于 JWT 令牌响应
class Token(BaseModel):
    access_token: str
    token_type: str

# 用于存储 JWT 令牌中的数据
class TokenData(BaseModel):
    username: Optional[str] = None

# 用户模型
class User(BaseModel):
    username: str
    disabled: Optional[bool] = None

# 扩展用户模型，包含密码哈希
class UserInDB(User):
    hashed_password: str

# TTS 请求模型，定义文本转语音的参数
class TTSRequest(BaseModel):
    text: str  # 要转换为语音的文本
    voice: Optional[str] = "zh-CN-XiaoxiaoNeural"  # 默认使用中文女声
    rate: Optional[str] = "+0%"  # 语速，0% 表示正常速度
    volume: Optional[str] = "+0%"  # 音量，0% 表示正常音量

# 模拟用户数据库
# 在实际应用中，应使用真实数据库并正确哈希密码
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "fakehashedsecret",  # 实际应用中应该是哈希值
        "disabled": False,
    }
}

# 设置 OAuth2 密码流认证
# tokenUrl 指定获取令牌的端点
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 验证密码函数
# 在实际应用中，应使用安全的密码哈希比较
def verify_password(plain_password, hashed_password):
    # 简化的密码验证，仅用于演示
    # 在生产环境中，应该使用 passlib 等库进行安全的密码验证
    return plain_password == "secret"  # 确保这里的密码与前端一致

# 从数据库获取用户
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

# 认证用户
def authenticate_user(fake_db, username: str, password: str):
    # 获取用户
    user = get_user(fake_db, username)
    if not user:
        return False
    # 验证密码
    if not verify_password(password, user.hashed_password):
        return False
    return user

# 创建访问令牌
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    # 复制数据以避免修改原始数据
    to_encode = data.copy()
    # 设置过期时间
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    # 添加过期时间到令牌数据
    to_encode.update({"exp": expire})
    # 使用 JWT 编码数据
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 获取当前用户
# 从请求中提取并验证 JWT 令牌
async def get_current_user(token: str = Depends(oauth2_scheme)):
    # 定义认证失败异常
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # 解码 JWT 令牌
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # 从令牌中提取用户名
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        # 创建令牌数据对象
        token_data = TokenData(username=username)
    except JWTError:
        # JWT 解码失败时抛出异常
        raise credentials_exception
    # 获取用户
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        # 用户不存在时抛出异常
        raise credentials_exception
    return user

# 获取当前活跃用户
# 检查用户是否被禁用
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        # 用户被禁用时抛出异常
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# 路由定义
# 令牌获取端点
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # 记录登录尝试
    print(f"Login attempt: {form_data.username}")
    # 认证用户
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        # 认证失败时记录并抛出异常
        print(f"Authentication failed for {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # 设置令牌过期时间
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # 创建访问令牌
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    # 记录令牌生成
    print(f"Token generated for {form_data.username}")
    # 返回令牌
    return {"access_token": access_token, "token_type": "bearer"}

# 文本转语音端点
@app.post("/tts")
async def text_to_speech(
    request: TTSRequest, 
    current_user: User = Depends(get_current_active_user)  # 需要认证
):
    # 记录 TTS 请求
    print(f"TTS request from {current_user.username}: {request.text[:30]}...")
    try:
        # 创建 edge-tts 通信对象
        # 使用请求中指定的参数
        communicate = edge_tts.Communicate(
            request.text,  # 要转换的文本
            request.voice,  # 语音选项
            rate=request.rate,  # 语速
            volume=request.volume  # 音量
        )
        
        # 将音频数据写入内存缓冲区
        audio_stream = io.BytesIO()
        # 异步迭代 edge-tts 流
        async for chunk in communicate.stream():
            # 只处理音频类型的数据块
            if chunk["type"] == "audio":
                audio_stream.write(chunk["data"])
        
        # 重置缓冲区位置到开始
        audio_stream.seek(0)
        
        # 返回音频流作为响应
        # 使用 StreamingResponse 可以直接流式传输音频数据
        return StreamingResponse(
            audio_stream,  # 音频数据流
            media_type="audio/mp3",  # 指定媒体类型
            headers={"Content-Disposition": "attachment; filename=speech.mp3"}  # 设置下载文件名
        )
    except Exception as e:
        # 记录错误
        print(f"TTS error: {str(e)}")
        # 返回 500 错误
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"TTS processing error: {str(e)}"
        )

# 获取可用语音列表端点
@app.get("/voices")
async def list_voices(current_user: User = Depends(get_current_active_user)):
    try:
        # 获取 edge-tts 支持的所有语音
        voices = await edge_tts.list_voices()
        return voices
    except Exception as e:
        # 返回 500 错误
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing voices: {str(e)}"
        )

# 根路径端点，用于检查 API 是否运行
@app.get("/")
async def root():
    return {"message": "Text-to-Speech API is running"}

# 启动服务器（当直接运行此文件时）
if __name__ == "__main__":
    import uvicorn
    # 使用 uvicorn 启动 FastAPI 应用
    # host="0.0.0.0" 表示监听所有网络接口
    # port=8000 指定端口
    # reload=True 启用热重载（开发模式）
    uvicorn.run("main:app", host="0.0.0.0", port=80, reload=True)