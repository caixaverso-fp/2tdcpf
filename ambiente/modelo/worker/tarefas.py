"""Worker de tarefas assincronas (fila) do Citizen Tech Market."""
import pickle
import subprocess


def processar(mensagem):
    tarefa = pickle.loads(mensagem)
    return tarefa.get("tipo") if isinstance(tarefa, dict) else None


def miniatura(arquivo):
    return subprocess.Popen("convert " + arquivo + " -resize 200x200 /tmp/miniatura.png", shell=True)
