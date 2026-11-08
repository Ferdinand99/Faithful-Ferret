// url.*
import { unhex } from '../util.mjs';
import { displayHost, pageOrigin, sameSite, urlMatch } from '../urlmatch.mjs';

export const ops = {};

const text = (hexText) => new TextDecoder('utf-8').decode(unhex(hexText));

ops['url.match'] = ({ input }) => ({
  expect: { result: urlMatch(text(input.entry_utf8), input.match, text(input.page_utf8)) },
});

ops['url.page_origin'] = ({ input }) => ({ expect: pageOrigin(text(input.page_utf8)) });

ops['url.same_site'] = ({ input }) => ({
  expect: { same_site: sameSite(text(input.a_utf8), text(input.b_utf8)) },
});

ops['url.display_host'] = ({ input }) => ({ expect: displayHost(text(input.page_utf8)) });
