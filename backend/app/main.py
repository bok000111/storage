from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
	return {"msg": f"Hello World from {__name__}"}