import numpy as np
import os
from python.core.logger import get_logger

logger = get_logger('vector_index')
INDEX_PATH = os.path.expanduser('~/.mahoraga/faiss.index')


class VectorIndex:
    """
    FAISS-backed similarity search for antibody vectors.
    Falls back to brute-force cosine search if faiss is unavailable.
    """

    DIM = 8

    def __init__(self):
        self.index = None
        self.metadata = []   # parallel list of antibody dicts
        self._init_index()

    def _init_index(self):
        try:
            import faiss
            self.index = faiss.IndexFlatL2(self.DIM)
            self._faiss = True
            logger.info('FAISS vector index initialised')
        except ImportError:
            self._faiss = False
            self._vectors = []
            logger.warning('faiss not available — using brute-force search')

    def add(self, antibody: dict):
        vec = self._antibody_to_vector(antibody)
        self.metadata.append(antibody)
        if self._faiss:
            import faiss
            self.index.add(np.array([vec], dtype='float32'))
        else:
            self._vectors.append(vec)

    def find_similar(self, telemetry: dict, top_k: int = 3) -> list:
        query = self._telemetry_to_vector(telemetry)
        if not self.metadata:
            return []

        if self._faiss:
            D, I = self.index.search(np.array([query], dtype='float32'), top_k)
            return [self.metadata[I[0][j]] for j in range(len(I[0]))
                    if I[0][j] < len(self.metadata) and D[0][j] < 2.0]
        else:
            if not self._vectors:
                return []
            vecs = np.array(self._vectors)
            dists = np.linalg.norm(vecs - query, axis=1)
            top = np.argsort(dists)[:top_k]
            return [self.metadata[i] for i in top if dists[i] < 2.0]

    def _telemetry_to_vector(self, t: dict) -> np.ndarray:
        return np.array([
            float(t.get('cpu', 0)) / 100,
            float(t.get('memory', 0)) / 100,
            float(t.get('connections', 0)) / 50,
            1.0 if t.get('is_sensitive') else 0.0,
            1.0 if t.get('event') == 'new_process' else 0.0,
            1.0 if t.get('source') == 'network' else 0.0,
            float(t.get('packet_size', 0)) / 65535,
            1.0 if t.get('event') == 'mass_file_modification' else 0.0,
        ], dtype='float32')

    def _antibody_to_vector(self, ab: dict) -> np.ndarray:
        import json
        t = {}
        try:
            t = json.loads(ab.get('vector_json', '{}'))
        except Exception:
            pass
        return self._telemetry_to_vector(t)
