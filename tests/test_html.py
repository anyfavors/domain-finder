from bs4 import BeautifulSoup
import domain_finder as domain


def test_write_html(tmp_path):
    cfg = domain.Config(html_out=tmp_path / "out.html")
    df = domain.DomainFinder(cfg)
    records = [domain.Candidate("foo","com",10,1.0,2,3,0.5,0)]
    import asyncio
    asyncio.run(df.write_html(records))
    html = (tmp_path / "out.html").read_text()
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    assert table is not None
    assert table.find_all("tr")
