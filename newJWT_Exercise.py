from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated, Union
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator
from datetime import datetime, timezone, timedelta, time, date

app = FastAPI()

UserDB = {}
EventsDB = {}

pwd_context = CryptContext(schemes= ["bcrypt"], deprecated= 'auto')
oAuth2 = OAuth2PasswordBearer(tokenUrl='token')

SECRET_KEY = "Key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10

class User(BaseModel):
    username: str
    email: Union[str, None] = None
    status: Union[bool, None] = None
    password: str

    @field_validator('username')
    def validateUsername(username):
        if username in UserDB:
            raise HTTPException(status_code=400, detail='This Username is Already in Use!')
        return username

class Token(BaseModel):
    access_token: str
    token_type: str

class Event(BaseModel):
    id: str
    title: str
    description: str
    eventDate: date
    eventHour: str
    notes: Union[list[str], None] = None
    performed: bool

    @field_validator('id')
    def validateID(id):
        if id in EventsDB:
            raise HTTPException(status_code=400, detail='This ID is Already in Use!')
        return id
    
    @field_validator('eventHour')
    def validateHour(eventHour):
        try:
            datetime.strptime(eventHour, '%H::%M::%S').time()
        except:
            raise HTTPException(status_code=400, detail="Hour Format Wrong")
        return eventHour
    


def hashPassword(password: str) -> str:
    return pwd_context.hash(password)

def validatePassword(password: str, hashesPassword: str) -> bool:
    return pwd_context.verify(password, hashesPassword)

def getUser(username: str) -> User:
    print(username)
    return UserDB[username] if username in UserDB else None

def authenticateUser(username: str, password: str) -> User:
    user = getUser(username)
    if not user or not (validatePassword(password, user.password) if user else False):
        raise HTTPException(status_code=401, detail="Invalid Authentication Credentials")
    elif user.status != None and not user.status:
        raise HTTPException(status_code=400, detail="User Unavalible")
    return user

def createToken(data: dict) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({'exp': exp})
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return token

def getCurrentUser(token: Annotated[str, Depends(oAuth2)]) -> User:
    credentials_exception = HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username = payload.get('username')
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = getUser(username=username)

    return user

def validateToken(token: Annotated[str, Depends(oAuth2)]):
    credentials_exception = HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username = payload.get('username')
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception


@app.post('/register')
async def register(user: Annotated[str, Depends(User)]):
    user.password = hashPassword(user.password)
    UserDB.update({user.username: user})
    return {"message": 'User Registered Succesfully', 'userlist': UserDB}


@app.post('/token')
async def login(formData: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = authenticateUser(formData.username, formData.password)
    access_token = createToken(data={'username': user.username})
    return Token(access_token=access_token, token_type="bearer")
    


@app.get('/user', dependencies=[Depends(validateToken)])
async def getAllUsers():
    return {'UserList': UserDB} if len(UserDB) > 0 else {'Message': "No Users Registered!"}


#------------------------------------------------------------------------------
#                                   EVENT STUFF                                                    
#------------------------------------------------------------------------------

@app.post('/event/create', dependencies=[Depends(validateToken)])
async def createEvent(event: Annotated[str, Depends(Event)]):
    EventsDB.update({event.id: event})
    return {'Message': 'Event Saved Succesfully!'}

@app.get('/event', dependencies=[Depends(validateToken)])
async def getEvents():
    return {'Events List': EventsDB} if len(EventsDB) > 0 else {'message': "No Events Registered!"}

@app.get('/event/{id}', dependencies=[Depends(validateToken)])
async def getEventsID(id: str):
    return {'Event Found': EventsDB[id]} if len(EventsDB) > 0 and id in EventsDB else {'message': "Event Not Found"}

@app.get('/eventPerformed', dependencies=[Depends(validateToken)])
async def getEventsPerformed():
    perfList = []
    indexList = list(filter(lambda x: EventsDB[x].performed == True, EventsDB))
    for x in indexList: perfList.append(EventsDB[x])
    return {'Events Performed List': perfList}

@app.get('/eventNotPerformed', dependencies=[Depends(validateToken)])
async def getEventsNotPerformed():
    perfList = []
    indexList = list(filter(lambda x: EventsDB[x].performed == False, EventsDB))
    for x in indexList: perfList.append(EventsDB[x])
    return {'Events Not Performed List': perfList}

@app.put('/updateEvent/{id}', dependencies=[Depends(validateToken)])
async def updateEvent(id: str, 
    title: str,
    description: str,
    eventDate: date,
    eventHour: str,
    notes: Union[list[str], None] = None,
    performed: bool = False
    ):
    if not id in EventsDB:
        raise HTTPException(status_code=400, detail="Event Not Found")
    del(EventsDB[id])
    event = Event(id=id, title=title, description=description, eventDate=eventDate, eventHour=eventHour, performed=performed, notes=notes)
    EventsDB.update({id: event})
    return event

@app.post('/event/addNotes/{id}', dependencies=[Depends(validateToken)])
async def addNotes(id: str, note: str):
    if not id in EventsDB:
        raise HTTPException(status_code=400, detail="Event Not Found")
    event = EventsDB[id]
    event.notes.append(note) 
    EventsDB.update({id: event})
    return event

@app.delete('/event/delete/{id}', dependencies=[Depends(validateToken)])
async def deleteEvent(id: str):
    if not id in EventsDB:
        raise HTTPException(status_code=400, detail="Event Not Found")
    elif EventsDB[id].performed:
        raise HTTPException(status_code=400, detail="It is Imposible to Delete Events that has Already been Performed")
    del(EventsDB[id])
    return {'Message': "Event Deleted Succesfully!"}