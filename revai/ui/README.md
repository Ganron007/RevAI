# RevAI Console

Enterprise product UI for the Remnux static-RE + LangGraph pipeline.

```bash
npm install
npm run dev      # Vite proxy → http://192.168.77.41:5000
npm run build
```

Deploy: `../../scripts/deploy.sh` builds the Console (`npm run build`) and copies `dist/` to `/opt/scripts/ui`.
