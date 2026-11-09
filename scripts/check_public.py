"""Offline publication guard. Reports locations and categories, never values."""
from pathlib import Path
import re
import sys

FILES = {
    '.gitignore', '.project-system.json', '.github/workflows/check.yml',
    'AGENTS.md', 'README.md', 'MASTER-SPEC.md', 'LICENSE', 'SECURITY.md',
    'scripts/check_public.py', 'tests/test_public.py',
    'skills/no-ai-slop/SKILL.md',
}
RULES = {
    'private-key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'token': r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b',
    'credential': r'''(?i)\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*["'][^"'\s]{8,}["']''',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'local-path': r'(?:/(?:Users|home)/[^\s/]+|[A-Z]:\\Users\\[^\s\\]+|fi[l]e://[^\s]+|~/(?:Documents|Desktop)/)',
    'ip-address': r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',
    'url-credentials': r'https?://[^\s/@]+:[^\s/@]+@',
}

def findings(text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for category, pattern in RULES.items():
            if re.search(pattern, line):
                found.append((number, category))
        for url in re.findall(r'https?://[^\s<>"\')]+', line):
            if 'github.com/' in url and not re.match(
                r'https://github\.com/bushkarev-max/no-ai-slop(?:[/.#?]|$)', url
            ):
                found.append((number, 'unapproved-github-url'))
    return found

def scan(root):
    issues = []
    seen = set()
    for p in root.rglob('*'):
        rel = p.relative_to(root)
        if '.git' in rel.parts or '__pycache__' in rel.parts:
            continue
        if p.is_symlink():
            issues.append((str(rel), 0, 'symlink'))
            continue
        if p.is_dir():
            continue
        name = rel.as_posix()
        seen.add(name)
        if name not in FILES:
            issues.append((name, 0, 'unapproved-file'))
        try:
            data = p.read_bytes()
            if b'\0' in data:
                raise ValueError('binary')
            text = data.decode('utf-8')
        except (UnicodeError, ValueError):
            issues.append((name, 0, 'non-text'))
            continue
        issues.extend((name, line, category) for line, category in findings(text))
        if name.startswith('skills/') and name.endswith('/SKILL.md'):
            folder = rel.parts[1]
            header = text.split('---', 2)
            if len(header) < 3 or header[0] != '' or not re.search(
                r'^name: ' + re.escape(folder) + r'$', header[1], re.M
            ) or not re.search(r'^description: .+', header[1], re.M):
                issues.append((name, 0, 'skill-frontmatter'))
    issues.extend((name, 0, 'missing-file') for name in sorted(FILES - seen))
    return issues

if __name__ == '__main__':
    result = scan(Path(__file__).resolve().parents[1])
    for name, line, category in result:
        print(f'{name}:{line}: {category}')
    print(f'{len(FILES)} expected files; {len(result)} findings')
    sys.exit(bool(result))
