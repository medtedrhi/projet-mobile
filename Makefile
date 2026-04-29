.PHONY: backend frontend test seed

backend:
	cd backend && uvicorn app.main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

test:
	cd backend && pytest
	cd frontend && npm run test

seed:
	python scripts/seed_demo.py
